//go:build linux

package main

import (
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"

	seccomp "github.com/elastic/go-seccomp-bpf"
	"golang.org/x/sys/unix"
)

const (
	pluginSandboxUID = 65534
	pluginSandboxGID = 65534

	pluginSandboxSocketDir  = "/run/go-plugin"
	pluginSandboxOldRootDir = "/.old-root"
	pluginSandboxProcDir    = "/proc"
	pluginSandboxTmpDir     = "/tmp"

	envPluginSandboxRoot          = "NS_PLUGIN_SANDBOX_ROOT"
	envPluginSandboxHostSocketDir = "NS_PLUGIN_SANDBOX_HOST_SOCKET_DIR"
	envPluginSandboxSocketDir     = "NS_PLUGIN_SANDBOX_SOCKET_DIR"
	envPluginSandboxStage         = "NS_PLUGIN_SANDBOX_STAGE"
	envPluginSandboxFailStep      = "NS_PLUGIN_SANDBOX_TEST_FAIL_STEP"
	envPluginUnixSocketDir        = "PLUGIN_UNIX_SOCKET_DIR"
	envPluginSandboxSeccompProbe  = "NS_PLUGIN_SANDBOX_SECCOMP_PROBE"

	pluginSandboxStageBootstrap = "bootstrap"
	pluginSandboxStageServe     = "serve"
)

var pluginSandboxReadonlyBindMounts = []string{
	"/lib",
	"/lib64",
	"/usr/lib",
	"/usr/lib64",
}

var (
	pluginSandboxMount     = unix.Mount
	pluginSandboxPivotRoot = unix.PivotRoot
	pluginSandboxUnmount   = unix.Unmount
	pluginSandboxExec      = unix.Exec
	pluginSandboxChdir     = os.Chdir
	pluginSandboxChown     = os.Chown
	pluginSandboxOpenFile  = os.OpenFile
	pluginSandboxRemove    = os.Remove
	pluginSandboxPrctl     = unix.Prctl
	pluginSandboxSetresgid = unix.Setresgid
	pluginSandboxSetresuid = unix.Setresuid
	pluginSandboxCapset    = func(hdr *unix.CapUserHeader, data *unix.CapUserData) error {
		return unix.Capset(hdr, data)
	}
	pluginSandboxMkdirTemp   = os.MkdirTemp
	pluginSandboxRemoveAll   = os.RemoveAll
	pluginSandboxLoadFilter  = seccomp.LoadFilter
	pluginSandboxExecveProbe = func() unix.Errno {
		_, _, errno := unix.Syscall(unix.SYS_EXECVE, 0, 0, 0)
		return errno
	}
	pluginSandboxClearAmbientCapabilities  = clearAmbientCapabilities
	pluginSandboxDropCapabilityBoundingSet = dropCapabilityBoundingSet
	pluginSandboxClearCapabilitySets       = clearCapabilitySets
)

type pluginSandboxSpec struct {
	rootDir         string
	hostSocketDir   string
	pluginSocketDir string
	uid             int
	gid             int
}

func newPluginSandboxSpec(runtimeDir, hostSocketDir string) (pluginSandboxSpec, error) {
	rootDir, err := filepath.Abs(filepath.Join(runtimeDir, "sandbox-root"))
	if err != nil {
		return pluginSandboxSpec{}, fmt.Errorf("resolve sandbox root: %w", err)
	}

	hostSocketDir, err = filepath.Abs(hostSocketDir)
	if err != nil {
		return pluginSandboxSpec{}, fmt.Errorf("resolve sandbox socket dir: %w", err)
	}

	spec := pluginSandboxSpec{
		rootDir:         filepath.Clean(rootDir),
		hostSocketDir:   filepath.Clean(hostSocketDir),
		pluginSocketDir: pluginSandboxSocketDir,
		uid:             pluginSandboxUID,
		gid:             pluginSandboxGID,
	}
	if err := spec.validate(); err != nil {
		return pluginSandboxSpec{}, err
	}
	return spec, nil
}

func loadPluginSandboxSpecFromEnv() (pluginSandboxSpec, error) {
	spec := pluginSandboxSpec{
		rootDir:         filepath.Clean(os.Getenv(envPluginSandboxRoot)),
		hostSocketDir:   filepath.Clean(os.Getenv(envPluginSandboxHostSocketDir)),
		pluginSocketDir: filepath.Clean(os.Getenv(envPluginSandboxSocketDir)),
		uid:             pluginSandboxUID,
		gid:             pluginSandboxGID,
	}
	if spec.pluginSocketDir == "." || spec.pluginSocketDir == "" {
		spec.pluginSocketDir = pluginSandboxSocketDir
	}
	if err := spec.validate(); err != nil {
		return pluginSandboxSpec{}, err
	}
	return spec, nil
}

func (s pluginSandboxSpec) validate() error {
	switch {
	case s.rootDir == "" || s.rootDir == ".":
		return fmt.Errorf("%s is not set", envPluginSandboxRoot)
	case !filepath.IsAbs(s.rootDir):
		return fmt.Errorf("sandbox root %q must be absolute", s.rootDir)
	case s.hostSocketDir == "" || s.hostSocketDir == ".":
		return fmt.Errorf("%s is not set", envPluginSandboxHostSocketDir)
	case !filepath.IsAbs(s.hostSocketDir):
		return fmt.Errorf("sandbox host socket dir %q must be absolute", s.hostSocketDir)
	case s.pluginSocketDir == "" || s.pluginSocketDir == ".":
		return fmt.Errorf("sandbox plugin socket dir is empty")
	case !filepath.IsAbs(s.pluginSocketDir):
		return fmt.Errorf("sandbox plugin socket dir %q must be absolute", s.pluginSocketDir)
	case s.uid < 0 || s.gid < 0:
		return fmt.Errorf("sandbox uid/gid must be non-negative")
	default:
		return nil
	}
}

func (s pluginSandboxSpec) env() []string {
	return []string{
		envPluginSandboxRoot + "=" + s.rootDir,
		envPluginSandboxHostSocketDir + "=" + s.hostSocketDir,
		envPluginSandboxSocketDir + "=" + s.pluginSocketDir,
		envPluginSandboxStage + "=" + pluginSandboxStageBootstrap,
	}
}

func (s pluginSandboxSpec) rootPath(path string) string {
	trimmed := strings.TrimPrefix(filepath.Clean(path), string(os.PathSeparator))
	if trimmed == "." {
		return s.rootDir
	}
	return filepath.Join(s.rootDir, trimmed)
}

func (s pluginSandboxSpec) pluginToHostAddr(pluginNet, pluginAddr string) (string, string, error) {
	if !isUnixNetwork(pluginNet) {
		return pluginNet, pluginAddr, nil
	}

	hostAddr, err := translateUnixSocketPath(pluginAddr, s.pluginSocketDir, s.hostSocketDir)
	if err != nil {
		return "", "", err
	}
	return pluginNet, hostAddr, nil
}

func (s pluginSandboxSpec) hostToPluginAddr(hostNet, hostAddr string) (string, string, error) {
	if !isUnixNetwork(hostNet) {
		return hostNet, hostAddr, nil
	}

	pluginAddr, err := translateUnixSocketPath(hostAddr, s.hostSocketDir, s.pluginSocketDir)
	if err != nil {
		return "", "", err
	}
	return hostNet, pluginAddr, nil
}

func translateUnixSocketPath(addr, fromDir, toDir string) (string, error) {
	addr = filepath.Clean(addr)
	fromDir = filepath.Clean(fromDir)
	toDir = filepath.Clean(toDir)

	rel, err := filepath.Rel(fromDir, addr)
	if err != nil {
		return "", fmt.Errorf("map unix socket %q from %q: %w", addr, fromDir, err)
	}
	if rel == ".." || strings.HasPrefix(rel, ".."+string(os.PathSeparator)) {
		return "", fmt.Errorf("unix socket %q is outside %q", addr, fromDir)
	}
	return filepath.Join(toDir, rel), nil
}

func isUnixNetwork(network string) bool {
	return strings.HasPrefix(network, "unix")
}

func applyPluginSandboxSysProcAttr(cmd *exec.Cmd) error {
	if cmd == nil {
		return fmt.Errorf("sandbox command is nil")
	}

	attr := cmd.SysProcAttr
	if attr == nil {
		attr = &syscall.SysProcAttr{}
	}

	attr.Cloneflags |= uintptr(syscall.CLONE_NEWUSER | syscall.CLONE_NEWNS | syscall.CLONE_NEWPID)
	attr.Pdeathsig = syscall.SIGKILL
	attr.GidMappingsEnableSetgroups = false
	attr.UidMappings = []syscall.SysProcIDMap{
		{ContainerID: 0, HostID: os.Geteuid(), Size: 1},
		{ContainerID: pluginSandboxUID, HostID: pluginSandboxUID, Size: 1},
	}
	attr.GidMappings = []syscall.SysProcIDMap{
		{ContainerID: 0, HostID: os.Getegid(), Size: 1},
		{ContainerID: pluginSandboxGID, HostID: pluginSandboxGID, Size: 1},
	}

	cmd.SysProcAttr = attr
	return nil
}

func ensurePluginSandbox() error {
	spec, err := loadPluginSandboxSpecFromEnv()
	if err != nil {
		return err
	}

	switch os.Getenv(envPluginSandboxStage) {
	case pluginSandboxStageBootstrap:
		return spec.bootstrapAndExec()
	case pluginSandboxStageServe:
		return spec.finalize()
	default:
		return fmt.Errorf("%s must be %q or %q", envPluginSandboxStage, pluginSandboxStageBootstrap, pluginSandboxStageServe)
	}
}

func (s pluginSandboxSpec) bootstrapAndExec() error {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	if err := s.prepareFilesystem(); err != nil {
		return err
	}
	if err := s.dropPrivilegesForReexec(); err != nil {
		return err
	}
	if err := sandboxFailpoint("reexec"); err != nil {
		return err
	}

	env := upsertEnv(os.Environ(), envPluginSandboxStage, pluginSandboxStageServe)
	env = upsertEnv(env, envPluginUnixSocketDir, s.pluginSocketDir)
	return pluginSandboxExec("/proc/self/exe", os.Args, env)
}

func (s pluginSandboxSpec) prepareFilesystem() error {
	if err := sandboxFailpoint("mount-private"); err != nil {
		return err
	}
	if err := pluginSandboxMount("", "/", "", uintptr(unix.MS_REC|unix.MS_PRIVATE), ""); err != nil {
		return fmt.Errorf("make mount namespace private: %w", err)
	}

	for _, dir := range []string{
		s.rootDir,
		s.rootPath("/run"),
		s.rootPath(s.pluginSocketDir),
		s.rootPath(pluginSandboxProcDir),
		s.rootPath(pluginSandboxTmpDir),
	} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return fmt.Errorf("create sandbox dir %q: %w", dir, err)
		}
	}
	if err := os.Chmod(s.rootPath(pluginSandboxTmpDir), 0o1777); err != nil {
		return fmt.Errorf("chmod sandbox tmp: %w", err)
	}

	if err := sandboxFailpoint("bind-socket"); err != nil {
		return err
	}
	if err := pluginSandboxMount(s.hostSocketDir, s.rootPath(s.pluginSocketDir), "", uintptr(unix.MS_BIND), ""); err != nil {
		return fmt.Errorf("bind mount sandbox socket dir: %w", err)
	}
	if err := pluginSandboxChown(s.rootPath(s.pluginSocketDir), s.uid, s.gid); err != nil {
		return fmt.Errorf("chown sandbox socket dir: %w", err)
	}
	if err := os.Chmod(s.rootPath(s.pluginSocketDir), 0o700); err != nil {
		return fmt.Errorf("chmod sandbox socket dir: %w", err)
	}

	for _, mountPath := range pluginSandboxReadonlyBindMounts {
		if err := s.bindReadOnlyPath(mountPath); err != nil {
			return err
		}
	}

	if err := sandboxFailpoint("mount-proc"); err != nil {
		return err
	}
	if err := pluginSandboxMount("proc", s.rootPath(pluginSandboxProcDir), "proc", uintptr(unix.MS_NOSUID|unix.MS_NODEV|unix.MS_NOEXEC), ""); err != nil {
		return fmt.Errorf("mount proc in sandbox: %w", err)
	}

	if err := sandboxFailpoint("mount-tmp"); err != nil {
		return err
	}
	if err := pluginSandboxMount("tmpfs", s.rootPath(pluginSandboxTmpDir), "tmpfs", uintptr(unix.MS_NOSUID|unix.MS_NODEV|unix.MS_NOEXEC), "mode=1777,size=16777216"); err != nil {
		return fmt.Errorf("mount tmpfs in sandbox: %w", err)
	}

	if err := pluginSandboxMount(s.rootDir, s.rootDir, "", uintptr(unix.MS_BIND|unix.MS_REC), ""); err != nil {
		return fmt.Errorf("bind sandbox root %q onto itself: %w", s.rootDir, err)
	}

	pivotOldRoot := s.rootPath(pluginSandboxOldRootDir)
	if err := os.MkdirAll(pivotOldRoot, 0o755); err != nil {
		return fmt.Errorf("create sandbox old root dir %q: %w", pivotOldRoot, err)
	}

	if err := sandboxFailpoint("pivot-root"); err != nil {
		return err
	}
	if err := pluginSandboxPivotRoot(s.rootDir, pivotOldRoot); err != nil {
		return fmt.Errorf("pivot_root sandbox root %q: %w", s.rootDir, err)
	}
	if err := pluginSandboxChdir("/"); err != nil {
		return fmt.Errorf("chdir sandbox root: %w", err)
	}
	if err := sandboxFailpoint("detach-old-root"); err != nil {
		return err
	}
	if err := pluginSandboxUnmount(pluginSandboxOldRootDir, unix.MNT_DETACH); err != nil {
		return fmt.Errorf("detach sandbox old root %q: %w", pluginSandboxOldRootDir, err)
	}
	if err := sandboxFailpoint("remove-old-root"); err != nil {
		return err
	}
	if err := pluginSandboxRemove(pluginSandboxOldRootDir); err != nil {
		return fmt.Errorf("remove sandbox old root dir %q: %w", pluginSandboxOldRootDir, err)
	}

	return nil
}

func (s pluginSandboxSpec) dropPrivilegesForReexec() error {
	if err := sandboxFailpoint("cap-ambient"); err != nil {
		return err
	}
	if err := pluginSandboxClearAmbientCapabilities(); err != nil {
		return fmt.Errorf("clear ambient capabilities: %w", err)
	}

	if err := sandboxFailpoint("cap-bounding"); err != nil {
		return err
	}
	if err := pluginSandboxDropCapabilityBoundingSet(); err != nil {
		return fmt.Errorf("drop capability bounding set: %w", err)
	}

	if err := pluginSandboxPrctl(unix.PR_SET_KEEPCAPS, 0, 0, 0, 0); err != nil {
		return fmt.Errorf("disable keepcaps: %w", err)
	}

	if err := sandboxFailpoint("setresgid"); err != nil {
		return err
	}
	if err := pluginSandboxSetresgid(s.gid, s.gid, s.gid); err != nil {
		return fmt.Errorf("drop gid to %d: %w", s.gid, err)
	}

	if err := sandboxFailpoint("setresuid"); err != nil {
		return err
	}
	if err := pluginSandboxSetresuid(s.uid, s.uid, s.uid); err != nil {
		return fmt.Errorf("drop uid to %d: %w", s.uid, err)
	}

	return nil
}

func (s pluginSandboxSpec) finalize() error {
	if os.Geteuid() != s.uid || os.Getegid() != s.gid {
		return fmt.Errorf("sandbox re-exec is still privileged: uid=%d gid=%d", os.Geteuid(), os.Getegid())
	}

	if err := sandboxFailpoint("cap-clear"); err != nil {
		return err
	}
	if err := pluginSandboxClearCapabilitySets(); err != nil {
		return fmt.Errorf("clear capability sets: %w", err)
	}
	if err := pluginSandboxClearAmbientCapabilities(); err != nil {
		return fmt.Errorf("clear ambient capabilities after re-exec: %w", err)
	}

	if err := sandboxFailpoint("seccomp"); err != nil {
		return err
	}
	if err := pluginSandboxLoadFilter(pluginSandboxSeccompFilter()); err != nil {
		return fmt.Errorf("load sandbox seccomp filter: %w", err)
	}

	return nil
}

func (s pluginSandboxSpec) bindReadOnlyPath(hostPath string) error {
	info, err := os.Stat(hostPath)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("stat sandbox support path %q: %w", hostPath, err)
	}

	target := s.rootPath(hostPath)
	if info.IsDir() {
		if err := os.MkdirAll(target, 0o755); err != nil {
			return fmt.Errorf("create sandbox bind dir %q: %w", target, err)
		}
		if err := pluginSandboxMount(hostPath, target, "", uintptr(unix.MS_BIND|unix.MS_REC), ""); err != nil {
			return fmt.Errorf("bind mount sandbox support dir %q: %w", hostPath, err)
		}
		if err := pluginSandboxMount("", target, "", uintptr(unix.MS_BIND|unix.MS_REMOUNT|unix.MS_RDONLY|unix.MS_REC), ""); err != nil {
			return fmt.Errorf("remount sandbox support dir %q read-only: %w", hostPath, err)
		}
		return nil
	}

	if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
		return fmt.Errorf("create sandbox bind parent %q: %w", filepath.Dir(target), err)
	}
	f, err := pluginSandboxOpenFile(target, os.O_CREATE, 0o644)
	if err != nil {
		return fmt.Errorf("create sandbox bind file %q: %w", target, err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("close sandbox bind file %q: %w", target, err)
	}
	if err := pluginSandboxMount(hostPath, target, "", uintptr(unix.MS_BIND), ""); err != nil {
		return fmt.Errorf("bind mount sandbox support file %q: %w", hostPath, err)
	}
	if err := pluginSandboxMount("", target, "", uintptr(unix.MS_BIND|unix.MS_REMOUNT|unix.MS_RDONLY), ""); err != nil {
		return fmt.Errorf("remount sandbox support file %q read-only: %w", hostPath, err)
	}
	return nil
}

func pluginSandboxSeccompFilter() seccomp.Filter {
	return seccomp.Filter{
		NoNewPrivs: true,
		Flag:       seccomp.FilterFlagTSync,
		Policy: seccomp.Policy{
			DefaultAction: seccomp.ActionErrno,
			Syscalls: []seccomp.SyscallGroup{
				{
					Action: seccomp.ActionAllow,
					Names: []string{
						"accept",
						"accept4",
						"arch_prctl",
						"bind",
						"brk",
						"clock_gettime",
						"clock_nanosleep",
						"clone",
						"clone3",
						"close",
						"connect",
						"dup",
						"dup3",
						"epoll_create1",
						"epoll_ctl",
						"epoll_pwait",
						"epoll_pwait2",
						"eventfd2",
						"exit",
						"exit_group",
						"fcntl",
						"fstat",
						"fsync",
						"futex",
						"getegid",
						"geteuid",
						"getgid",
						"getpeername",
						"getpid",
						"getppid",
						"getsockname",
						"getsockopt",
						"gettid",
						"getuid",
						"ioctl",
						"listen",
						"lseek",
						"madvise",
						"membarrier",
						"mmap",
						"mprotect",
						"munmap",
						"nanosleep",
						"newfstatat",
						"openat",
						"pipe2",
						"poll",
						"ppoll",
						"pread64",
						"prlimit64",
						"pselect6",
						"read",
						"readlink",
						"readlinkat",
						"readv",
						"recvfrom",
						"recvmsg",
						"recvmmsg",
						"restart_syscall",
						"rseq",
						"rt_sigaction",
						"rt_sigprocmask",
						"rt_sigreturn",
						"sched_getaffinity",
						"sched_yield",
						"sendmsg",
						"sendmmsg",
						"sendto",
						"set_robust_list",
						"set_tid_address",
						"setsockopt",
						"shutdown",
						"sigaltstack",
						"socket",
						"socketpair",
						"statx",
						"tgkill",
						"uname",
						"unlink",
						"unlinkat",
						"write",
						"writev",
					},
				},
			},
		},
	}
}

func clearAmbientCapabilities() error {
	return pluginSandboxPrctl(unix.PR_CAP_AMBIENT, unix.PR_CAP_AMBIENT_CLEAR_ALL, 0, 0, 0)
}

func dropCapabilityBoundingSet() error {
	for capID := 0; capID <= int(unix.CAP_LAST_CAP); capID++ {
		err := pluginSandboxPrctl(unix.PR_CAPBSET_DROP, uintptr(capID), 0, 0, 0)
		if err == nil || err == unix.EINVAL {
			continue
		}
		return err
	}
	return nil
}

func clearCapabilitySets() error {
	hdr := unix.CapUserHeader{Version: unix.LINUX_CAPABILITY_VERSION_3}
	var data [2]unix.CapUserData
	return pluginSandboxCapset(&hdr, &data[0])
}

func sandboxFailpoint(step string) error {
	if os.Getenv(envPluginSandboxFailStep) == step {
		return fmt.Errorf("sandbox failpoint at %s", step)
	}
	return nil
}

func upsertEnv(env []string, key, value string) []string {
	prefix := key + "="
	for i, entry := range env {
		if strings.HasPrefix(entry, prefix) {
			out := append([]string(nil), env...)
			out[i] = prefix + value
			return out
		}
	}
	return append(env, prefix+value)
}

func runPluginSandboxSeccompProbe() error {
	socketDir, err := pluginSandboxMkdirTemp("", "netforge-seccomp")
	if err != nil {
		return fmt.Errorf("create probe socket dir: %w", err)
	}
	defer pluginSandboxRemoveAll(socketDir)

	if err := pluginSandboxLoadFilter(pluginSandboxSeccompFilter()); err != nil {
		return fmt.Errorf("load seccomp filter: %w", err)
	}

	if err := pluginSandboxProbeListenAndDial("tcp", "127.0.0.1:0"); err != nil {
		return fmt.Errorf("tcp networking after seccomp failed: %w", err)
	}
	if err := pluginSandboxProbeListenAndDial("unix", filepath.Join(socketDir, "probe.sock")); err != nil {
		return fmt.Errorf("unix networking after seccomp failed: %w", err)
	}

	errno := pluginSandboxExecveProbe()
	if errno != unix.EPERM {
		return fmt.Errorf("expected execve to be blocked with EPERM, got %v", errno)
	}

	return nil
}

func pluginSandboxProbeListenAndDial(network, address string) error {
	listener, err := net.Listen(network, address)
	if err != nil {
		return err
	}
	defer listener.Close()

	errCh := make(chan error, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			errCh <- err
			return
		}
		defer conn.Close()

		buf := make([]byte, 4)
		if _, err := conn.Read(buf); err != nil {
			errCh <- err
			return
		}
		errCh <- nil
	}()

	dialer := net.Dialer{Timeout: 2 * time.Second}
	conn, err := dialer.Dial(network, listener.Addr().String())
	if err != nil {
		return err
	}
	if _, err := conn.Write([]byte("ping")); err != nil {
		conn.Close()
		return err
	}
	if err := conn.Close(); err != nil {
		return err
	}

	select {
	case err := <-errCh:
		return err
	case <-time.After(2 * time.Second):
		return errors.New("accept probe timed out")
	}
}
