//go:build linux

package main

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"testing"

	seccomp "github.com/elastic/go-seccomp-bpf"
	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netns"
	"golang.org/x/sys/unix"
)

func resetSandboxTestHooks(t *testing.T) {
	t.Helper()

	readonlyBindMounts := append([]string(nil), pluginSandboxReadonlyBindMounts...)
	mount := pluginSandboxMount
	chroot := pluginSandboxChroot
	execFn := pluginSandboxExec
	chdir := pluginSandboxChdir
	chown := pluginSandboxChown
	openFile := pluginSandboxOpenFile
	prctl := pluginSandboxPrctl
	setresgid := pluginSandboxSetresgid
	setresuid := pluginSandboxSetresuid
	capset := pluginSandboxCapset
	mkdirTemp := pluginSandboxMkdirTemp
	removeAll := pluginSandboxRemoveAll
	loadFilter := pluginSandboxLoadFilter
	execveProbe := pluginSandboxExecveProbe
	clearAmbient := pluginSandboxClearAmbientCapabilities
	dropBounding := pluginSandboxDropCapabilityBoundingSet
	clearCaps := pluginSandboxClearCapabilitySets

	t.Cleanup(func() {
		pluginSandboxReadonlyBindMounts = readonlyBindMounts
		pluginSandboxMount = mount
		pluginSandboxChroot = chroot
		pluginSandboxExec = execFn
		pluginSandboxChdir = chdir
		pluginSandboxChown = chown
		pluginSandboxOpenFile = openFile
		pluginSandboxPrctl = prctl
		pluginSandboxSetresgid = setresgid
		pluginSandboxSetresuid = setresuid
		pluginSandboxCapset = capset
		pluginSandboxMkdirTemp = mkdirTemp
		pluginSandboxRemoveAll = removeAll
		pluginSandboxLoadFilter = loadFilter
		pluginSandboxExecveProbe = execveProbe
		pluginSandboxClearAmbientCapabilities = clearAmbient
		pluginSandboxDropCapabilityBoundingSet = dropBounding
		pluginSandboxClearCapabilitySets = clearCaps
	})
}

func TestNewPluginSandboxSpec(t *testing.T) {
	spec, err := newPluginSandboxSpec("/tmp/netforge", "/tmp/netforge/plugin-dir")
	if err != nil {
		t.Fatalf("newPluginSandboxSpec failed: %v", err)
	}

	if spec.rootDir != "/tmp/netforge/sandbox-root" {
		t.Fatalf("unexpected sandbox root: %q", spec.rootDir)
	}
	if spec.hostSocketDir != "/tmp/netforge/plugin-dir" {
		t.Fatalf("unexpected sandbox host socket dir: %q", spec.hostSocketDir)
	}
	if spec.pluginSocketDir != pluginSandboxSocketDir {
		t.Fatalf("unexpected sandbox plugin socket dir: %q", spec.pluginSocketDir)
	}
	if spec.uid != pluginSandboxUID || spec.gid != pluginSandboxGID {
		t.Fatalf("unexpected sandbox uid/gid: %d/%d", spec.uid, spec.gid)
	}
}

func TestLoadPluginSandboxSpecFromEnv(t *testing.T) {
	root := t.TempDir()
	socketDir := t.TempDir()

	t.Setenv(envPluginSandboxRoot, root)
	t.Setenv(envPluginSandboxHostSocketDir, socketDir)
	t.Setenv(envPluginSandboxSocketDir, pluginSandboxSocketDir)

	spec, err := loadPluginSandboxSpecFromEnv()
	if err != nil {
		t.Fatalf("loadPluginSandboxSpecFromEnv failed: %v", err)
	}
	if spec.rootDir != root {
		t.Fatalf("unexpected rootDir: %q", spec.rootDir)
	}
	if spec.hostSocketDir != socketDir {
		t.Fatalf("unexpected hostSocketDir: %q", spec.hostSocketDir)
	}
	if spec.pluginSocketDir != pluginSandboxSocketDir {
		t.Fatalf("unexpected pluginSocketDir: %q", spec.pluginSocketDir)
	}
}

func TestPluginSandboxSpecValidateErrors(t *testing.T) {
	for _, tc := range []struct {
		name string
		spec pluginSandboxSpec
	}{
		{name: "missing root", spec: pluginSandboxSpec{hostSocketDir: "/tmp/socket", pluginSocketDir: pluginSandboxSocketDir}},
		{name: "relative root", spec: pluginSandboxSpec{rootDir: "root", hostSocketDir: "/tmp/socket", pluginSocketDir: pluginSandboxSocketDir}},
		{name: "missing socket dir", spec: pluginSandboxSpec{rootDir: "/tmp/root", pluginSocketDir: pluginSandboxSocketDir}},
		{name: "relative socket dir", spec: pluginSandboxSpec{rootDir: "/tmp/root", hostSocketDir: "socket", pluginSocketDir: pluginSandboxSocketDir}},
		{name: "relative plugin dir", spec: pluginSandboxSpec{rootDir: "/tmp/root", hostSocketDir: "/tmp/socket", pluginSocketDir: "run/go-plugin"}},
		{name: "negative ids", spec: pluginSandboxSpec{rootDir: "/tmp/root", hostSocketDir: "/tmp/socket", pluginSocketDir: pluginSandboxSocketDir, uid: -1, gid: -1}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := tc.spec.validate(); err == nil {
				t.Fatal("expected validate error")
			}
		})
	}
}

func TestApplyPluginSandboxSysProcAttr(t *testing.T) {
	cmd := exec.Command("true")
	if err := applyPluginSandboxSysProcAttr(cmd); err != nil {
		t.Fatalf("applyPluginSandboxSysProcAttr failed: %v", err)
	}

	attr := cmd.SysProcAttr
	if attr == nil {
		t.Fatal("expected SysProcAttr to be configured")
	}

	wantFlags := uintptr(syscall.CLONE_NEWUSER | syscall.CLONE_NEWNS | syscall.CLONE_NEWPID)
	if attr.Cloneflags&wantFlags != wantFlags {
		t.Fatalf("sandbox clone flags mismatch: got %#x want %#x", attr.Cloneflags, wantFlags)
	}
	if attr.Pdeathsig != syscall.SIGKILL {
		t.Fatalf("unexpected Pdeathsig: got %v want %v", attr.Pdeathsig, syscall.SIGKILL)
	}
	if attr.GidMappingsEnableSetgroups {
		t.Fatal("expected setgroups to be disabled for gid mappings")
	}
	if len(attr.UidMappings) != 2 || attr.UidMappings[0].ContainerID != 0 || attr.UidMappings[1].ContainerID != pluginSandboxUID {
		t.Fatalf("unexpected uid mappings: %+v", attr.UidMappings)
	}
	if len(attr.GidMappings) != 2 || attr.GidMappings[0].ContainerID != 0 || attr.GidMappings[1].ContainerID != pluginSandboxGID {
		t.Fatalf("unexpected gid mappings: %+v", attr.GidMappings)
	}
}

func TestApplyPluginSandboxSysProcAttrRejectsNilCommand(t *testing.T) {
	if err := applyPluginSandboxSysProcAttr(nil); err == nil {
		t.Fatal("expected applyPluginSandboxSysProcAttr to reject nil cmd")
	}
}

func TestTranslateUnixSocketPath(t *testing.T) {
	got, err := translateUnixSocketPath("/host/plugin-dir/plugin.sock", "/host/plugin-dir", pluginSandboxSocketDir)
	if err != nil {
		t.Fatalf("translateUnixSocketPath failed: %v", err)
	}
	if got != "/run/go-plugin/plugin.sock" {
		t.Fatalf("unexpected translated socket path: %q", got)
	}

	if _, err := translateUnixSocketPath("/tmp/plugin.sock", "/host/plugin-dir", pluginSandboxSocketDir); err == nil {
		t.Fatal("expected translateUnixSocketPath to reject paths outside the socket dir")
	}
}

func TestPluginSandboxHelpers(t *testing.T) {
	spec := pluginSandboxSpec{
		rootDir:         "/tmp/sandbox-root",
		hostSocketDir:   "/tmp/plugin-dir",
		pluginSocketDir: pluginSandboxSocketDir,
		uid:             pluginSandboxUID,
		gid:             pluginSandboxGID,
	}

	if got := spec.rootPath("/proc"); got != "/tmp/sandbox-root/proc" {
		t.Fatalf("unexpected rootPath result: %q", got)
	}
	if got := spec.rootPath("/"); got != "/tmp/sandbox-root" {
		t.Fatalf("unexpected rootPath for root: %q", got)
	}

	env := spec.env()
	if !slices.Contains(env, envPluginSandboxRoot+"="+spec.rootDir) {
		t.Fatalf("sandbox env missing root: %+v", env)
	}
	if !slices.Contains(env, envPluginSandboxHostSocketDir+"="+spec.hostSocketDir) {
		t.Fatalf("sandbox env missing host socket dir: %+v", env)
	}
	if !slices.Contains(env, envPluginSandboxStage+"="+pluginSandboxStageBootstrap) {
		t.Fatalf("sandbox env missing bootstrap stage: %+v", env)
	}

	if !isUnixNetwork("unix") || !isUnixNetwork("unixpacket") || isUnixNetwork("tcp") {
		t.Fatal("isUnixNetwork returned unexpected result")
	}

	replaced := upsertEnv([]string{"A=1", "B=2"}, "A", "9")
	if !slices.Contains(replaced, "A=9") || slices.Contains(replaced, "A=1") {
		t.Fatalf("upsertEnv did not replace entry: %+v", replaced)
	}
	appended := upsertEnv([]string{"A=1"}, "C", "3")
	if !slices.Contains(appended, "C=3") {
		t.Fatalf("upsertEnv did not append entry: %+v", appended)
	}

	t.Setenv(envPluginSandboxFailStep, "cap-clear")
	if err := sandboxFailpoint("cap-clear"); err == nil {
		t.Fatal("expected sandbox failpoint error")
	}
	if err := sandboxFailpoint("other"); err != nil {
		t.Fatalf("unexpected failpoint error for other step: %v", err)
	}
}

func TestPluginSandboxSeccompFilterDefinition(t *testing.T) {
	filter := pluginSandboxSeccompFilter()
	if !filter.NoNewPrivs {
		t.Fatal("expected seccomp filter to set no_new_privs")
	}
	if filter.Flag != 1 {
		t.Fatalf("unexpected seccomp filter flag: %v", filter.Flag)
	}
	if err := filter.Policy.Validate(); err != nil {
		t.Fatalf("invalid seccomp policy: %v", err)
	}
	if len(filter.Policy.Syscalls) != 1 {
		t.Fatalf("unexpected syscall group count: %d", len(filter.Policy.Syscalls))
	}
	names := filter.Policy.Syscalls[0].Names
	for _, want := range []string{"socket", "setsockopt", "read", "write", "exit_group"} {
		if !slices.Contains(names, want) {
			t.Fatalf("seccomp policy missing syscall %q", want)
		}
	}
}

func TestStagePluginChildBinary(t *testing.T) {
	selfBinary, err := os.Executable()
	if err != nil {
		t.Fatalf("os.Executable failed: %v", err)
	}

	runtimeDir := t.TempDir()
	staged, err := stagePluginChildBinary(selfBinary, runtimeDir)
	if err != nil {
		t.Fatalf("stagePluginChildBinary failed: %v", err)
	}
	if filepath.Dir(staged) != runtimeDir {
		t.Fatalf("unexpected staged binary path: %q", staged)
	}
	info, err := os.Stat(staged)
	if err != nil {
		t.Fatalf("stat staged binary failed: %v", err)
	}
	if info.Mode()&0o111 == 0 {
		t.Fatalf("expected staged binary to be executable, mode=%#o", info.Mode().Perm())
	}

	stagedAgain, err := stagePluginChildBinary(selfBinary, runtimeDir)
	if err != nil {
		t.Fatalf("second stagePluginChildBinary failed: %v", err)
	}
	if stagedAgain != staged {
		t.Fatalf("expected staged binary to be reused: %q vs %q", stagedAgain, staged)
	}
}

func TestRunPluginModeRequiresSandbox(t *testing.T) {
	if err := runPluginMode(); err == nil {
		t.Fatal("expected runPluginMode to fail without sandbox env")
	}
}

func TestRunMainPluginModeError(t *testing.T) {
	t.Setenv("NS_PLUGIN_MODE", "1")
	if err := runMain(); err == nil {
		t.Fatal("expected runMain to fail in plugin mode without sandbox env")
	}
}

func TestStartCmdInNamedNamespaceRejectsMissingNamespace(t *testing.T) {
	cmd := exec.Command("true")
	if err := startCmdInNamedNamespace(cmd, "netforge-missing-ns"); err == nil {
		t.Fatal("expected startCmdInNamedNamespace to fail for missing namespace")
	}
}

func TestPluginSandboxSeccompFilterAllowsNetworkingAndBlocksExecve(t *testing.T) {
	bin := buildPackageBinary(t)
	cmd := exec.Command(bin)
	cmd.Env = append(os.Environ(), envPluginSandboxSeccompProbe+"=1")
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("seccomp probe failed: %v\n%s", err, output)
	}
}

func TestEnsurePluginSandboxRejectsUnknownStage(t *testing.T) {
	t.Setenv(envPluginSandboxRoot, t.TempDir())
	t.Setenv(envPluginSandboxHostSocketDir, t.TempDir())
	t.Setenv(envPluginSandboxSocketDir, pluginSandboxSocketDir)
	t.Setenv(envPluginSandboxStage, "unknown")

	if err := ensurePluginSandbox(); err == nil {
		t.Fatal("expected ensurePluginSandbox to reject unknown stage")
	}
}

func TestPluginSandboxPrepareFilesystem(t *testing.T) {
	resetSandboxTestHooks(t)

	root := t.TempDir()
	socketDir := t.TempDir()
	spec := pluginSandboxSpec{
		rootDir:         filepath.Join(root, "sandbox-root"),
		hostSocketDir:   socketDir,
		pluginSocketDir: pluginSandboxSocketDir,
		uid:             pluginSandboxUID,
		gid:             pluginSandboxGID,
	}

	pluginSandboxReadonlyBindMounts = nil

	var mounts []string
	pluginSandboxMount = func(source, target, fstype string, flags uintptr, data string) error {
		mounts = append(mounts, fmt.Sprintf("%s|%s|%s|%d|%s", source, target, fstype, flags, data))
		return nil
	}
	pluginSandboxChown = func(string, int, int) error { return nil }
	var chrootPath string
	pluginSandboxChroot = func(path string) error {
		chrootPath = path
		return nil
	}
	var chdirPath string
	pluginSandboxChdir = func(path string) error {
		chdirPath = path
		return nil
	}

	if err := spec.prepareFilesystem(); err != nil {
		t.Fatalf("prepareFilesystem failed: %v", err)
	}

	for _, path := range []string{
		spec.rootDir,
		spec.rootPath("/run"),
		spec.rootPath(spec.pluginSocketDir),
		spec.rootPath(pluginSandboxProcDir),
		spec.rootPath(pluginSandboxTmpDir),
	} {
		if info, err := os.Stat(path); err != nil || !info.IsDir() {
			t.Fatalf("expected sandbox path %q to exist as a dir, err=%v", path, err)
		}
	}

	if info, err := os.Stat(spec.rootPath(pluginSandboxTmpDir)); err != nil {
		t.Fatalf("stat sandbox tmp failed: %v", err)
	} else if info.Mode().Perm() != 0o777 {
		t.Fatalf("unexpected sandbox tmp perms: got %#o want %#o", info.Mode().Perm(), os.FileMode(0o777))
	}
	if chrootPath != spec.rootDir {
		t.Fatalf("unexpected chroot path: got %q want %q", chrootPath, spec.rootDir)
	}
	if chdirPath != "/" {
		t.Fatalf("unexpected chdir path: got %q want %q", chdirPath, "/")
	}

	wantTargets := []string{
		fmt.Sprintf("|/||%d|", uintptr(unix.MS_REC|unix.MS_PRIVATE)),
		fmt.Sprintf("%s|%s||%d|", socketDir, spec.rootPath(spec.pluginSocketDir), uintptr(unix.MS_BIND)),
		fmt.Sprintf("proc|%s|proc|%d|", spec.rootPath(pluginSandboxProcDir), uintptr(unix.MS_NOSUID|unix.MS_NODEV|unix.MS_NOEXEC)),
		fmt.Sprintf("tmpfs|%s|tmpfs|%d|mode=1777,size=16777216", spec.rootPath(pluginSandboxTmpDir), uintptr(unix.MS_NOSUID|unix.MS_NODEV|unix.MS_NOEXEC)),
	}
	for _, want := range wantTargets {
		if !slices.Contains(mounts, want) {
			t.Fatalf("prepareFilesystem mount calls missing %q: %+v", want, mounts)
		}
	}
}

func TestPluginSandboxBindReadOnlyPath(t *testing.T) {
	resetSandboxTestHooks(t)

	root := t.TempDir()
	hostDir := filepath.Join(t.TempDir(), "dir")
	hostFileDir := t.TempDir()
	hostFile := filepath.Join(hostFileDir, "libtest.so")
	if err := os.MkdirAll(hostDir, 0o755); err != nil {
		t.Fatalf("mkdir host dir failed: %v", err)
	}
	if err := os.WriteFile(hostFile, []byte("content"), 0o644); err != nil {
		t.Fatalf("write host file failed: %v", err)
	}

	spec := pluginSandboxSpec{rootDir: root}
	var mounts []string
	pluginSandboxMount = func(source, target, fstype string, flags uintptr, data string) error {
		mounts = append(mounts, fmt.Sprintf("%s|%s|%d", source, target, flags))
		return nil
	}

	if err := spec.bindReadOnlyPath(filepath.Join(t.TempDir(), "missing")); err != nil {
		t.Fatalf("bindReadOnlyPath missing path failed: %v", err)
	}
	if err := spec.bindReadOnlyPath(hostDir); err != nil {
		t.Fatalf("bindReadOnlyPath dir failed: %v", err)
	}
	if err := spec.bindReadOnlyPath(hostFile); err != nil {
		t.Fatalf("bindReadOnlyPath file failed: %v", err)
	}

	if _, err := os.Stat(spec.rootPath(hostDir)); err != nil {
		t.Fatalf("expected sandbox dir bind target to exist: %v", err)
	}
	if _, err := os.Stat(spec.rootPath(hostFile)); err != nil {
		t.Fatalf("expected sandbox file bind target to exist: %v", err)
	}
	if len(mounts) != 4 {
		t.Fatalf("unexpected bind mount count: got %d want 4 (%+v)", len(mounts), mounts)
	}
}

func TestPluginSandboxDropPrivilegesForReexec(t *testing.T) {
	resetSandboxTestHooks(t)

	spec := pluginSandboxSpec{uid: 1234, gid: 4321}
	var calls []string
	pluginSandboxClearAmbientCapabilities = func() error {
		calls = append(calls, "clear-ambient")
		return nil
	}
	pluginSandboxDropCapabilityBoundingSet = func() error {
		calls = append(calls, "drop-bounding")
		return nil
	}
	pluginSandboxPrctl = func(option int, arg2, arg3, arg4, arg5 uintptr) error {
		if option != unix.PR_SET_KEEPCAPS {
			t.Fatalf("unexpected prctl option: %d", option)
		}
		calls = append(calls, "keepcaps-off")
		return nil
	}
	pluginSandboxSetresgid = func(rgid, egid, sgid int) error {
		calls = append(calls, fmt.Sprintf("gid=%d/%d/%d", rgid, egid, sgid))
		return nil
	}
	pluginSandboxSetresuid = func(ruid, euid, suid int) error {
		calls = append(calls, fmt.Sprintf("uid=%d/%d/%d", ruid, euid, suid))
		return nil
	}

	if err := spec.dropPrivilegesForReexec(); err != nil {
		t.Fatalf("dropPrivilegesForReexec failed: %v", err)
	}

	want := []string{
		"clear-ambient",
		"drop-bounding",
		"keepcaps-off",
		"gid=4321/4321/4321",
		"uid=1234/1234/1234",
	}
	if !slices.Equal(calls, want) {
		t.Fatalf("unexpected privilege drop calls: got %+v want %+v", calls, want)
	}
}

func TestPluginSandboxFinalize(t *testing.T) {
	resetSandboxTestHooks(t)

	spec := pluginSandboxSpec{
		uid: os.Geteuid(),
		gid: os.Getegid(),
	}

	var calls []string
	pluginSandboxClearCapabilitySets = func() error {
		calls = append(calls, "clear-capsets")
		return nil
	}
	pluginSandboxClearAmbientCapabilities = func() error {
		calls = append(calls, "clear-ambient")
		return nil
	}
	pluginSandboxLoadFilter = func(filter seccomp.Filter) error {
		if !filter.NoNewPrivs {
			t.Fatal("expected seccomp filter to set no_new_privs")
		}
		calls = append(calls, "load-filter")
		return nil
	}

	if err := spec.finalize(); err != nil {
		t.Fatalf("finalize failed: %v", err)
	}

	want := []string{"clear-capsets", "clear-ambient", "load-filter"}
	if !slices.Equal(calls, want) {
		t.Fatalf("unexpected finalize calls: got %+v want %+v", calls, want)
	}
}

func TestPluginSandboxBootstrapAndExec(t *testing.T) {
	resetSandboxTestHooks(t)

	root := t.TempDir()
	socketDir := t.TempDir()
	spec := pluginSandboxSpec{
		rootDir:         filepath.Join(root, "sandbox-root"),
		hostSocketDir:   socketDir,
		pluginSocketDir: pluginSandboxSocketDir,
		uid:             pluginSandboxUID,
		gid:             pluginSandboxGID,
	}

	pluginSandboxReadonlyBindMounts = nil
	pluginSandboxMount = func(string, string, string, uintptr, string) error { return nil }
	pluginSandboxChown = func(string, int, int) error { return nil }
	pluginSandboxChroot = func(string) error { return nil }
	pluginSandboxChdir = func(string) error { return nil }
	pluginSandboxClearAmbientCapabilities = func() error { return nil }
	pluginSandboxDropCapabilityBoundingSet = func() error { return nil }
	pluginSandboxPrctl = func(int, uintptr, uintptr, uintptr, uintptr) error { return nil }
	pluginSandboxSetresgid = func(int, int, int) error { return nil }
	pluginSandboxSetresuid = func(int, int, int) error { return nil }

	wantErr := fmt.Errorf("exec sentinel")
	var execPath string
	var execArgs []string
	var execEnv []string
	pluginSandboxExec = func(path string, args []string, env []string) error {
		execPath = path
		execArgs = append([]string(nil), args...)
		execEnv = append([]string(nil), env...)
		return wantErr
	}

	err := spec.bootstrapAndExec()
	if err == nil || err.Error() != wantErr.Error() {
		t.Fatalf("bootstrapAndExec error mismatch: got %v want %v", err, wantErr)
	}
	if execPath != "/proc/self/exe" {
		t.Fatalf("unexpected exec path: got %q want %q", execPath, "/proc/self/exe")
	}
	if !slices.Equal(execArgs, os.Args) {
		t.Fatalf("unexpected exec args: got %+v want %+v", execArgs, os.Args)
	}
	if !slices.Contains(execEnv, envPluginSandboxStage+"="+pluginSandboxStageServe) {
		t.Fatalf("exec env missing serve stage: %+v", execEnv)
	}
	if !slices.Contains(execEnv, envPluginUnixSocketDir+"="+pluginSandboxSocketDir) {
		t.Fatalf("exec env missing plugin socket dir: %+v", execEnv)
	}
}

func TestCapabilityHelpers(t *testing.T) {
	resetSandboxTestHooks(t)

	var prctlCalls []string
	pluginSandboxPrctl = func(option int, arg2, arg3, arg4, arg5 uintptr) error {
		prctlCalls = append(prctlCalls, fmt.Sprintf("%d:%d", option, arg2))
		return nil
	}
	var capsetCalled bool
	pluginSandboxCapset = func(hdr *unix.CapUserHeader, data *unix.CapUserData) error {
		capsetCalled = true
		if hdr.Version != unix.LINUX_CAPABILITY_VERSION_3 {
			t.Fatalf("unexpected capability header version: %d", hdr.Version)
		}
		if data == nil {
			t.Fatal("expected capability data")
		}
		return nil
	}

	if err := clearAmbientCapabilities(); err != nil {
		t.Fatalf("clearAmbientCapabilities failed: %v", err)
	}
	if err := dropCapabilityBoundingSet(); err != nil {
		t.Fatalf("dropCapabilityBoundingSet failed: %v", err)
	}
	if err := clearCapabilitySets(); err != nil {
		t.Fatalf("clearCapabilitySets failed: %v", err)
	}

	if len(prctlCalls) != 1+int(unix.CAP_LAST_CAP)+1 {
		t.Fatalf("unexpected prctl call count: got %d", len(prctlCalls))
	}
	if !capsetCalled {
		t.Fatal("expected capset to be called")
	}
}

func TestRunPluginSandboxSeccompProbe(t *testing.T) {
	resetSandboxTestHooks(t)

	var loaded bool
	pluginSandboxLoadFilter = func(filter seccomp.Filter) error {
		loaded = true
		if !filter.NoNewPrivs {
			t.Fatal("expected seccomp filter to set no_new_privs")
		}
		return nil
	}
	pluginSandboxExecveProbe = func() unix.Errno { return unix.EPERM }

	if err := runPluginSandboxSeccompProbe(); err != nil {
		t.Fatalf("runPluginSandboxSeccompProbe failed: %v", err)
	}
	if !loaded {
		t.Fatal("expected seccomp filter to be loaded")
	}
}

func TestSandboxHelperProcess(t *testing.T) {
	mode := os.Getenv("NETFORGE_SANDBOX_HELPER")
	if mode == "" {
		return
	}

	root := os.Getenv(envPluginSandboxRoot)
	socketDir := os.Getenv(envPluginSandboxHostSocketDir)
	spec := pluginSandboxSpec{
		rootDir:         root,
		hostSocketDir:   socketDir,
		pluginSocketDir: pluginSandboxSocketDir,
		uid:             pluginSandboxUID,
		gid:             pluginSandboxGID,
	}

	var err error
	switch mode {
	case "ensure-bootstrap-fail-mount-private":
		err = ensurePluginSandbox()
	case "prepare-filesystem-fail-chroot":
		err = unix.Unshare(unix.CLONE_NEWNS)
		if err == nil {
			err = spec.prepareFilesystem()
		}
	case "drop-privileges-fail-cap-ambient":
		err = spec.dropPrivilegesForReexec()
	case "ensure-stage-serve-privileged":
		err = ensurePluginSandbox()
	case "capability-helpers":
		if err = clearAmbientCapabilities(); err == nil {
			err = dropCapabilityBoundingSet()
		}
		if err == nil {
			err = clearCapabilitySets()
		}
	default:
		err = fmt.Errorf("unknown helper mode %q", mode)
	}

	if err == nil {
		return
	}
	t.Fatal(err)
}

func TestSandboxHelperSubprocesses(t *testing.T) {
	requireIntegration(t)

	root := t.TempDir()
	socketDir := t.TempDir()
	marker := filepath.Join(socketDir, "marker.txt")
	if err := os.WriteFile(marker, []byte("ok"), 0o644); err != nil {
		t.Fatalf("write marker failed: %v", err)
	}

	runHelper := func(t *testing.T, mode string, failpoint string, wantErr string) {
		t.Helper()

		cmd := exec.Command(os.Args[0], "-test.run=TestSandboxHelperProcess$")
		cmd.Env = append(os.Environ(),
			"NETFORGE_SANDBOX_HELPER="+mode,
			envPluginSandboxRoot+"="+root,
			envPluginSandboxHostSocketDir+"="+socketDir,
			envPluginSandboxSocketDir+"="+pluginSandboxSocketDir,
		)
		if mode == "ensure-bootstrap-fail-mount-private" {
			cmd.Env = append(cmd.Env, envPluginSandboxStage+"="+pluginSandboxStageBootstrap)
		}
		if mode == "ensure-stage-serve-privileged" {
			cmd.Env = append(cmd.Env, envPluginSandboxStage+"="+pluginSandboxStageServe)
		}
		if failpoint != "" {
			cmd.Env = append(cmd.Env, envPluginSandboxFailStep+"="+failpoint)
		}

		output, err := cmd.CombinedOutput()
		if err == nil {
			t.Fatalf("expected helper %q to fail, output=%s", mode, output)
		}
		if wantErr != "" && !strings.Contains(string(output), wantErr) {
			t.Fatalf("helper %q output %q does not contain %q", mode, output, wantErr)
		}
	}

	t.Run("ensure bootstrap failpoint", func(t *testing.T) {
		runHelper(t, "ensure-bootstrap-fail-mount-private", "mount-private", "sandbox failpoint at mount-private")
	})

	t.Run("prepare filesystem through bind mounts", func(t *testing.T) {
		runHelper(t, "prepare-filesystem-fail-chroot", "chroot", "sandbox failpoint at chroot")

		socketTarget := filepath.Join(root, "run", "go-plugin")
		if _, err := os.Stat(socketTarget); err != nil {
			t.Fatalf("expected sandbox socket target to exist, got: %v", err)
		}
	})

	t.Run("drop privileges failpoint", func(t *testing.T) {
		runHelper(t, "drop-privileges-fail-cap-ambient", "cap-ambient", "sandbox failpoint at cap-ambient")
	})

	t.Run("ensure stage serve privileged error", func(t *testing.T) {
		runHelper(t, "ensure-stage-serve-privileged", "", "sandbox re-exec is still privileged")
	})

	t.Run("capability helpers", func(t *testing.T) {
		cmd := exec.Command(os.Args[0], "-test.run=TestSandboxHelperProcess$")
		cmd.Env = append(os.Environ(), "NETFORGE_SANDBOX_HELPER=capability-helpers")
		output, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("capability helper failed: %v\n%s", err, output)
		}
	})
}

func TestStartNamespacePluginFailsClosedOnSandboxBootstrapError(t *testing.T) {
	requireIntegration(t)

	cfg, _, bin := setupPluginSandboxFixture(t, "210")
	for _, step := range []string{"bind-socket", "mount-proc", "chroot", "setresgid", "setresuid", "cap-clear", "seccomp"} {
		t.Run(step, func(t *testing.T) {
			t.Setenv(envPluginSandboxFailStep, step)

			proc, err := startNamespacePlugin(bin, t.TempDir(), cfg)
			if err == nil {
				if proc != nil {
					proc.Stop()
				}
				t.Fatalf("expected sandbox failpoint %q to abort plugin startup", step)
			}
		})
	}
}

func assertPluginSandboxed(t *testing.T, proc *runningPlugin) {
	t.Helper()

	if proc == nil || proc.pid <= 0 {
		t.Fatalf("expected running plugin with pid, got %+v", proc)
	}

	for _, nsName := range []string{"user", "mnt", "pid"} {
		hostNS := mustReadlink(t, filepath.Join("/proc/self/ns", nsName))
		childNS := mustReadlink(t, fmt.Sprintf("/proc/%d/ns/%s", proc.pid, nsName))
		if hostNS == childNS {
			t.Fatalf("expected child %s namespace to differ from host: %q", nsName, childNS)
		}
	}

	rootTarget := mustReadlink(t, fmt.Sprintf("/proc/%d/root", proc.pid))
	if filepath.Clean(rootTarget) != filepath.Clean(proc.sandbox.rootDir) {
		t.Fatalf("sandbox root mismatch: got %q want %q", rootTarget, proc.sandbox.rootDir)
	}

	status := readProcStatus(t, proc.pid)
	if status["NoNewPrivs"] != "1" {
		t.Fatalf("expected NoNewPrivs=1, got %q", status["NoNewPrivs"])
	}
	if status["Seccomp"] != "2" {
		t.Fatalf("expected Seccomp=2, got %q", status["Seccomp"])
	}
	if trimHexZero(status["CapEff"]) != "" {
		t.Fatalf("expected CapEff to be zero, got %q", status["CapEff"])
	}
	if trimHexZero(status["CapPrm"]) != "" {
		t.Fatalf("expected CapPrm to be zero, got %q", status["CapPrm"])
	}

	uidFields := strings.Fields(status["Uid"])
	if len(uidFields) < 2 || uidFields[0] != "65534" || uidFields[1] != "65534" {
		t.Fatalf("expected sandbox uid 65534, got %q", status["Uid"])
	}
	gidFields := strings.Fields(status["Gid"])
	if len(gidFields) < 2 || gidFields[0] != "65534" || gidFields[1] != "65534" {
		t.Fatalf("expected sandbox gid 65534, got %q", status["Gid"])
	}
}

func setupPluginSandboxFixture(t *testing.T, suffix string) (NSConfig, netns.NsHandle, string) {
	t.Helper()

	token := suffix + uniqueNamespaceToken()
	if len(token) > 8 {
		token = token[:8]
	}
	parentName := "d" + token
	nsName := "tns" + token
	listenPort := freeLocalTCPPort(t)
	cfg := NSConfig{
		Name:       nsName,
		VLANID:     200,
		IfName:     parentName + ".200",
		IPCIDR:     "10.20.0.2/24",
		MAC:        "02:00:00:00:20:02",
		Gateway:    "",
		ListenPort: listenPort,
		OpenPort:   listenPort,
	}

	cleanupHostLink(cfg.IfName)
	cleanupHostLink(parentName)
	_ = netns.DeleteNamed(nsName)

	dummy := &netlink.Dummy{LinkAttrs: netlink.NewLinkAttrs()}
	dummy.LinkAttrs.Name = parentName
	if err := netlink.LinkAdd(dummy); err != nil {
		t.Fatalf("create dummy parent failed: %v", err)
	}
	parent, err := netlink.LinkByName(parentName)
	if err != nil {
		t.Fatalf("lookup dummy parent failed: %v", err)
	}
	if err := netlink.LinkSetUp(parent); err != nil {
		t.Fatalf("bring dummy parent up failed: %v", err)
	}

	ns, err := setupNamespaceNetwork(parentName, cfg)
	if err != nil {
		t.Fatalf("setupNamespaceNetwork failed: %v", err)
	}

	t.Cleanup(func() {
		_ = deleteLinkInNamespace(ns, cfg.IfName)
		_ = ns.Close()
		_ = netns.DeleteNamed(nsName)
		cleanupHostLink(parentName)
		cleanupHostLink(cfg.IfName)
	})

	return cfg, ns, buildPackageBinary(t)
}

func readProcStatus(t *testing.T, pid int) map[string]string {
	t.Helper()

	f, err := os.Open(fmt.Sprintf("/proc/%d/status", pid))
	if err != nil {
		t.Fatalf("open proc status failed: %v", err)
	}
	defer f.Close()

	status := make(map[string]string)
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		key, value, ok := strings.Cut(line, ":")
		if ok {
			status[key] = strings.TrimSpace(value)
		}
	}
	if err := scanner.Err(); err != nil {
		t.Fatalf("scan proc status failed: %v", err)
	}
	return status
}

func mustReadlink(t *testing.T, path string) string {
	t.Helper()

	target, err := os.Readlink(path)
	if err != nil {
		t.Fatalf("readlink %s failed: %v", path, err)
	}
	return target
}

func trimHexZero(value string) string {
	return strings.TrimLeft(strings.TrimSpace(value), "0")
}
