//go:build linux

package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	cgroups "github.com/containerd/cgroups/v3"
	"github.com/containerd/cgroups/v3/cgroup2"
)

const pluginCgroupPrefix = "netforge"

const (
	pluginCgroupMountpoint      = "/sys/fs/cgroup"
	pluginCgroupPidsMax         = 128
	pluginCgroupMemoryMaxBytes  = 256 << 20
	pluginCgroupCPUQuotaMicros  = 100000
	pluginCgroupCPUPeriodMicros = 100000
)

type pluginCgroup interface {
	ConfigureCommand(cmd *exec.Cmd) error
	Kill() error
	Delete() error
	Close() error
	Path() string
}

type managedPluginCgroup struct {
	manager *cgroup2.Manager
	path    string
	dir     *os.File
}

var (
	pluginCgroupsMode           = cgroups.Mode
	pluginCgroupNestedGroupPath = func(group string) (string, error) {
		return filepath.Join(string(os.PathSeparator), group), nil
	}
	pluginCgroupNewManager = func(group string, resources *cgroup2.Resources) (*cgroup2.Manager, error) {
		return cgroup2.NewManager("/sys/fs/cgroup", group, resources)
	}
	pluginCgroupNow     = time.Now
	pluginCgroupOpenDir = os.Open
	pluginCgroupFactory = newPluginCgroup
)

func (c *managedPluginCgroup) ConfigureCommand(cmd *exec.Cmd) error {
	if cmd == nil {
		return fmt.Errorf("plugin command is nil")
	}
	if c == nil || c.dir == nil {
		return fmt.Errorf("plugin cgroup %q does not have an open cgroup fd", c.path)
	}

	attr := cmd.SysProcAttr
	if attr == nil {
		attr = &syscall.SysProcAttr{}
	}
	attr.UseCgroupFD = true
	attr.CgroupFD = int(c.dir.Fd())
	cmd.SysProcAttr = attr
	return nil
}

func (c *managedPluginCgroup) Kill() error {
	return c.manager.Kill()
}

func (c *managedPluginCgroup) Delete() error {
	return c.manager.Delete()
}

func (c *managedPluginCgroup) Close() error {
	if c == nil || c.dir == nil {
		return nil
	}
	err := c.dir.Close()
	c.dir = nil
	return err
}

func (c *managedPluginCgroup) Path() string {
	return c.path
}

func newPluginCgroup(namespace string) (pluginCgroup, error) {
	mode := pluginCgroupsMode()
	if mode != cgroups.Unified {
		return nil, fmt.Errorf("plugin cgroup requires unified cgroup v2 mode, got %s", pluginCgroupModeString(mode))
	}

	groupName := pluginCgroupLeaf(namespace)
	groupPath, err := pluginCgroupNestedGroupPath(groupName)
	if err != nil {
		return nil, fmt.Errorf("build plugin cgroup path for %q: %w", namespace, err)
	}

	resources := defaultPluginCgroupResources()
	manager, err := pluginCgroupNewManager(groupPath, resources)
	if err != nil {
		return nil, fmt.Errorf("create plugin cgroup %q: %w", groupPath, err)
	}

	cgroupDir, err := pluginCgroupOpenDir(pluginCgroupDirPath(groupPath))
	if err != nil {
		_ = manager.Delete()
		return nil, fmt.Errorf("open plugin cgroup dir %q: %w", groupPath, err)
	}

	return &managedPluginCgroup{
		manager: manager,
		path:    groupPath,
		dir:     cgroupDir,
	}, nil
}

func defaultPluginCgroupResources() *cgroup2.Resources {
	memoryMax := int64(pluginCgroupMemoryMaxBytes)
	pidsMax := int64(pluginCgroupPidsMax)
	cpuQuota := int64(pluginCgroupCPUQuotaMicros)
	cpuPeriod := uint64(pluginCgroupCPUPeriodMicros)
	oomGroup := true

	return &cgroup2.Resources{
		CPU: &cgroup2.CPU{
			Max: cgroup2.NewCPUMax(&cpuQuota, &cpuPeriod),
		},
		Memory: &cgroup2.Memory{
			Max:      &memoryMax,
			OOMGroup: &oomGroup,
		},
		Pids: &cgroup2.Pids{
			Max: pidsMax,
		},
	}
}

func pluginCgroupDirPath(groupPath string) string {
	return filepath.Join(pluginCgroupMountpoint, strings.TrimPrefix(groupPath, string(os.PathSeparator)))
}

func pluginCgroupLeaf(namespace string) string {
	sanitized := sanitizePluginCgroupComponent(namespace)
	return fmt.Sprintf("%s-%s-%d-%d", pluginCgroupPrefix, sanitized, os.Getpid(), pluginCgroupNow().UnixNano())
}

func sanitizePluginCgroupComponent(name string) string {
	name = strings.TrimSpace(name)
	if name == "" {
		return "plugin"
	}

	var b strings.Builder
	b.Grow(len(name))
	lastDash := false
	for _, r := range name {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '-', r == '_', r == '.':
			b.WriteRune(r)
			lastDash = false
		default:
			if !lastDash {
				b.WriteByte('-')
				lastDash = true
			}
		}
	}

	sanitized := strings.Trim(b.String(), "-")
	if sanitized == "" {
		return "plugin"
	}
	return sanitized
}

func pluginCgroupModeString(mode cgroups.CGMode) string {
	switch mode {
	case cgroups.Unified:
		return "unified"
	case cgroups.Hybrid:
		return "hybrid"
	case cgroups.Legacy:
		return "legacy"
	case cgroups.Unavailable:
		return "unavailable"
	default:
		return fmt.Sprintf("unknown(%d)", mode)
	}
}

func cleanupPluginCgroup(cgroup pluginCgroup) {
	if cgroup == nil {
		return
	}
	_ = cgroup.Close()
	_ = cgroup.Kill()
	_ = cgroup.Delete()
}
