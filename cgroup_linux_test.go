//go:build linux

package main

import (
	"errors"
	"os"
	"os/exec"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	cgroups "github.com/containerd/cgroups/v3"
	"github.com/containerd/cgroups/v3/cgroup2"
)

type fakePluginCgroup struct {
	path      string
	addedPIDs []uint64
	addErr    error
	killed    bool
	deleted   bool
}

func (f *fakePluginCgroup) AddProc(pid uint64) error {
	f.addedPIDs = append(f.addedPIDs, pid)
	return f.addErr
}

func (f *fakePluginCgroup) Kill() error {
	f.killed = true
	return nil
}

func (f *fakePluginCgroup) Delete() error {
	f.deleted = true
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
	factory := pluginCgroupFactory

	t.Cleanup(func() {
		pluginCgroupsMode = mode
		pluginCgroupNestedGroupPath = nested
		pluginCgroupNewManager = newManager
		pluginCgroupNow = now
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

	cgroup, err := newPluginCgroup("ns /with spaces")
	if err != nil {
		t.Fatalf("newPluginCgroup failed: %v", err)
	}

	wantLeaf := "ns-with-spaces"
	if !strings.HasPrefix(suffix, pluginCgroupPrefix+"/") {
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
	if resources.CPU != nil || resources.Memory != nil || resources.Pids != nil || len(resources.Devices) != 0 {
		t.Fatalf("expected empty cgroup resources, got %+v", resources)
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

	if !fake.killed || !fake.deleted {
		t.Fatalf("expected cleanup to kill and delete cgroup, got %+v", fake)
	}

	cleanupPluginCgroup(nil)
}

func TestNamespaceCmdRunnerAttachToCgroup(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		cmd := exec.Command("sleep", "30")
		if err := cmd.Start(); err != nil {
			t.Fatalf("cmd.Start failed: %v", err)
		}
		defer func() {
			_ = cmd.Process.Kill()
			_, _ = cmd.Process.Wait()
		}()

		fake := &fakePluginCgroup{path: "/netforge/test"}
		runner := &namespaceCmdRunner{cmd: cmd, cgroup: fake}

		if err := runner.attachToCgroup(); err != nil {
			t.Fatalf("attachToCgroup failed: %v", err)
		}
		if !slices.Equal(fake.addedPIDs, []uint64{uint64(cmd.Process.Pid)}) {
			t.Fatalf("unexpected cgroup add pid calls: %+v", fake.addedPIDs)
		}
		if fake.killed || fake.deleted {
			t.Fatalf("did not expect cleanup on successful attach: %+v", fake)
		}
	})

	t.Run("failure cleans up", func(t *testing.T) {
		cmd := exec.Command("sleep", "30")
		if err := cmd.Start(); err != nil {
			t.Fatalf("cmd.Start failed: %v", err)
		}

		fake := &fakePluginCgroup{
			path:   "/netforge/test",
			addErr: errors.New("boom"),
		}
		runner := &namespaceCmdRunner{cmd: cmd, cgroup: fake}

		if err := runner.attachToCgroup(); err == nil {
			t.Fatal("expected attachToCgroup to fail")
		}
		if !fake.killed || !fake.deleted {
			t.Fatalf("expected cleanup on failed attach: %+v", fake)
		}
	})
}

func TestRunningPluginStopCleansUpCgroup(t *testing.T) {
	stub := &stubNamespaceService{}
	fake := &fakePluginCgroup{}

	proc := &runningPlugin{
		rpc:    stub,
		cgroup: fake,
	}
	proc.Stop()

	if !fake.killed || !fake.deleted {
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
	if !strings.HasPrefix(leaf, "ns1-") {
		t.Fatalf("unexpected cgroup leaf prefix: %q", leaf)
	}
	if !strings.Contains(leaf, "-123000000456") {
		t.Fatalf("unexpected cgroup leaf timestamp: %q", leaf)
	}
	if !strings.Contains(leaf, "-"+strconv.Itoa(os.Getpid())+"-") {
		t.Fatalf("unexpected cgroup leaf pid: %q", leaf)
	}
}
