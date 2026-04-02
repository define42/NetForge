//go:build linux

package main

import (
	"errors"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	cgroups "github.com/containerd/cgroups/v3"
	"github.com/containerd/cgroups/v3/cgroup2"
)

type fakePluginCgroup struct {
	path         string
	configureErr error
	configured   bool
	useCgroupFD  bool
	cgroupFD     int
	killed       bool
	deleted      bool
	closed       bool
}

func (f *fakePluginCgroup) ConfigureCommand(cmd *exec.Cmd) error {
	if f.configureErr != nil {
		return f.configureErr
	}
	f.configured = true
	if cmd != nil {
		attr := cmd.SysProcAttr
		if attr == nil {
			attr = &syscall.SysProcAttr{}
		}
		attr.UseCgroupFD = true
		attr.CgroupFD = 42
		cmd.SysProcAttr = attr
		f.useCgroupFD = attr.UseCgroupFD
		f.cgroupFD = attr.CgroupFD
	}
	return nil
}

func (f *fakePluginCgroup) Kill() error {
	f.killed = true
	return nil
}

func (f *fakePluginCgroup) Delete() error {
	f.deleted = true
	return nil
}

func (f *fakePluginCgroup) Close() error {
	f.closed = true
	return nil
}

func (f *fakePluginCgroup) Path() string {
	return f.path
}

func resetPluginCgroupTestHooks(t *testing.T) {
	t.Helper()

	mode := pluginCgroupsMode
	nested := pluginCgroupNestedGroupPath
	newManager := pluginCgroupNewManager
	now := pluginCgroupNow
	openDir := pluginCgroupOpenDir
	factory := pluginCgroupFactory

	t.Cleanup(func() {
		pluginCgroupsMode = mode
		pluginCgroupNestedGroupPath = nested
		pluginCgroupNewManager = newManager
		pluginCgroupNow = now
		pluginCgroupOpenDir = openDir
		pluginCgroupFactory = factory
	})
}

func TestNewPluginCgroup(t *testing.T) {
	resetPluginCgroupTestHooks(t)

	fixedNow := time.Unix(1700000000, 123)
	pluginCgroupsMode = func() cgroups.CGMode { return cgroups.Unified }
	pluginCgroupNow = func() time.Time { return fixedNow }

	var suffix string
	pluginCgroupNestedGroupPath = func(value string) (string, error) {
		suffix = value
		return "/" + value, nil
	}

	var group string
	var resources *cgroup2.Resources
	pluginCgroupNewManager = func(path string, res *cgroup2.Resources) (*cgroup2.Manager, error) {
		group = path
		resources = res
		return &cgroup2.Manager{}, nil
	}
	pluginCgroupOpenDir = func(path string) (*os.File, error) {
		if want := pluginCgroupDirPath(group); path != want {
			t.Fatalf("unexpected cgroup dir path: got %q want %q", path, want)
		}
		return os.Open(t.TempDir())
	}

	cgroup, err := newPluginCgroup("ns /with spaces")
	if err != nil {
		t.Fatalf("newPluginCgroup failed: %v", err)
	}
	t.Cleanup(func() {
		_ = cgroup.Close()
	})

	wantLeaf := "ns-with-spaces"
	if !strings.HasPrefix(suffix, pluginCgroupPrefix+"-") {
		t.Fatalf("unexpected cgroup suffix: %q", suffix)
	}
	if !strings.Contains(suffix, wantLeaf) {
		t.Fatalf("cgroup suffix %q does not contain sanitized name %q", suffix, wantLeaf)
	}
	if group != "/"+suffix {
		t.Fatalf("unexpected cgroup path: got %q want %q", group, "/"+suffix)
	}
	if cgroup.Path() != group {
		t.Fatalf("unexpected cgroup Path(): got %q want %q", cgroup.Path(), group)
	}
	if resources == nil {
		t.Fatal("expected cgroup resources to be set")
	}
	if resources.CPU == nil || resources.Memory == nil || resources.Pids == nil {
		t.Fatalf("expected cpu, memory, and pids resources, got %+v", resources)
	}
	if resources.Pids.Max != pluginCgroupPidsMax {
		t.Fatalf("unexpected pids.max: got %d want %d", resources.Pids.Max, pluginCgroupPidsMax)
	}
	if resources.Memory.Max == nil || *resources.Memory.Max != pluginCgroupMemoryMaxBytes {
		t.Fatalf("unexpected memory.max: got %+v want %d", resources.Memory.Max, pluginCgroupMemoryMaxBytes)
	}
	if resources.Memory.OOMGroup == nil || !*resources.Memory.OOMGroup {
		t.Fatalf("expected oom.group to be enabled, got %+v", resources.Memory.OOMGroup)
	}
	wantCPUMax := cgroup2.NewCPUMax(func() *int64 {
		v := int64(pluginCgroupCPUQuotaMicros)
		return &v
	}(), func() *uint64 {
		v := uint64(pluginCgroupCPUPeriodMicros)
		return &v
	}())
	if resources.CPU.Max != wantCPUMax {
		t.Fatalf("unexpected cpu.max: got %q want %q", resources.CPU.Max, wantCPUMax)
	}
}

func TestNewPluginCgroupRejectsUnsupportedMode(t *testing.T) {
	resetPluginCgroupTestHooks(t)

	pluginCgroupsMode = func() cgroups.CGMode { return cgroups.Legacy }
	if _, err := newPluginCgroup("ns1"); err == nil {
		t.Fatal("expected newPluginCgroup to reject non-unified cgroups mode")
	}
}

func TestCleanupPluginCgroup(t *testing.T) {
	fake := &fakePluginCgroup{}
	cleanupPluginCgroup(fake)

	if !fake.closed || !fake.killed || !fake.deleted {
		t.Fatalf("expected cleanup to kill and delete cgroup, got %+v", fake)
	}

	cleanupPluginCgroup(nil)
}

func TestManagedPluginCgroupConfigureCommand(t *testing.T) {
	file, err := os.Open(t.TempDir())
	if err != nil {
		t.Fatalf("open temp dir failed: %v", err)
	}
	t.Cleanup(func() {
		_ = file.Close()
	})

	cmd := exec.Command("true")
	cgroup := &managedPluginCgroup{
		path: "/netforge/test",
		dir:  file,
	}

	if err := cgroup.ConfigureCommand(cmd); err != nil {
		t.Fatalf("ConfigureCommand failed: %v", err)
	}
	if cmd.SysProcAttr == nil {
		t.Fatal("expected SysProcAttr to be configured")
	}
	if !cmd.SysProcAttr.UseCgroupFD {
		t.Fatal("expected UseCgroupFD=true")
	}
	if got, want := cmd.SysProcAttr.CgroupFD, int(file.Fd()); got != want {
		t.Fatalf("unexpected CgroupFD: got %d want %d", got, want)
	}
}

func TestNewNamespaceCmdRunnerConfiguresCgroupBeforeStart(t *testing.T) {
	resetPluginCgroupTestHooks(t)

	fake := &fakePluginCgroup{path: "/netforge/test"}
	pluginCgroupFactory = func(namespace string) (pluginCgroup, error) {
		return fake, nil
	}

	cmd := exec.Command("true")
	runner, err := newNamespaceCmdRunner(nil, cmd, "ns1", pluginSandboxSpec{})
	if err != nil {
		t.Fatalf("newNamespaceCmdRunner failed: %v", err)
	}
	_ = runner

	if !fake.configured {
		t.Fatal("expected cgroup to configure command before start")
	}
	if !fake.useCgroupFD {
		t.Fatal("expected cgroup to set UseCgroupFD")
	}
	if fake.cgroupFD == 0 {
		t.Fatal("expected cgroup to set a non-zero cgroup fd")
	}
	if cmd.SysProcAttr == nil {
		t.Fatal("expected SysProcAttr to be set")
	}
	if want := uintptr(syscall.CLONE_NEWUSER | syscall.CLONE_NEWNS | syscall.CLONE_NEWPID); cmd.SysProcAttr.Cloneflags&want != want {
		t.Fatalf("expected sandbox clone flags to remain set, got %#x want mask %#x", cmd.SysProcAttr.Cloneflags, want)
	}
}

func TestNewNamespaceCmdRunnerCgroupConfigureFailureCleansUp(t *testing.T) {
	resetPluginCgroupTestHooks(t)

	fake := &fakePluginCgroup{
		path:         "/netforge/test",
		configureErr: errors.New("boom"),
	}
	pluginCgroupFactory = func(namespace string) (pluginCgroup, error) {
		return fake, nil
	}

	cmd := exec.Command("true")
	if _, err := newNamespaceCmdRunner(nil, cmd, "ns1", pluginSandboxSpec{}); err == nil {
		t.Fatal("expected newNamespaceCmdRunner to fail")
	}
	if !fake.closed || !fake.killed || !fake.deleted {
		t.Fatalf("expected cleanup on failed cgroup configuration: %+v", fake)
	}
}

func TestRunningPluginStopCleansUpCgroup(t *testing.T) {
	stub := &stubNamespaceService{}
	fake := &fakePluginCgroup{}

	proc := &runningPlugin{
		rpc:    stub,
		cgroup: fake,
	}
	proc.Stop()

	if !fake.closed || !fake.killed || !fake.deleted {
		t.Fatalf("expected Stop to clean up cgroup, got %+v", fake)
	}
	if proc.cgroup != nil {
		t.Fatal("expected Stop to clear cgroup reference")
	}
}

func TestPluginCgroupModeStringAndSanitize(t *testing.T) {
	if got := pluginCgroupModeString(cgroups.Unified); got != "unified" {
		t.Fatalf("unexpected unified mode string: %q", got)
	}
	if got := pluginCgroupModeString(cgroups.Hybrid); got != "hybrid" {
		t.Fatalf("unexpected hybrid mode string: %q", got)
	}
	if got := pluginCgroupModeString(cgroups.Legacy); got != "legacy" {
		t.Fatalf("unexpected legacy mode string: %q", got)
	}
	if got := pluginCgroupModeString(cgroups.Unavailable); got != "unavailable" {
		t.Fatalf("unexpected unavailable mode string: %q", got)
	}

	if got := sanitizePluginCgroupComponent(" ns/$ weird\tname "); got != "ns-weird-name" {
		t.Fatalf("unexpected sanitized cgroup component: %q", got)
	}
	if got := sanitizePluginCgroupComponent(""); got != "plugin" {
		t.Fatalf("unexpected empty-name sanitized cgroup component: %q", got)
	}
}

func TestPluginCgroupLeafIncludesPidAndTime(t *testing.T) {
	resetPluginCgroupTestHooks(t)

	pluginCgroupNow = func() time.Time {
		return time.Unix(123, 456)
	}

	leaf := pluginCgroupLeaf("ns1")
	if !strings.HasPrefix(leaf, pluginCgroupPrefix+"-ns1-") {
		t.Fatalf("unexpected cgroup leaf prefix: %q", leaf)
	}
	if !strings.Contains(leaf, "-123000000456") {
		t.Fatalf("unexpected cgroup leaf timestamp: %q", leaf)
	}
	if !strings.Contains(leaf, "-"+strconv.Itoa(os.Getpid())+"-") {
		t.Fatalf("unexpected cgroup leaf pid: %q", leaf)
	}
}
