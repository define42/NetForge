//go:build linux

package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	cgroups "github.com/containerd/cgroups/v3"
	"github.com/containerd/cgroups/v3/cgroup2"
)

const pluginCgroupPrefix = "netforge"

type pluginCgroup interface {
	AddProc(pid uint64) error
	Kill() error
	Delete() error
	Path() string
}

type managedPluginCgroup struct {
	manager *cgroup2.Manager
	path    string
}

var (
	pluginCgroupsMode           = cgroups.Mode
	pluginCgroupNestedGroupPath = cgroup2.NestedGroupPath
	pluginCgroupNewManager      = func(group string, resources *cgroup2.Resources) (*cgroup2.Manager, error) {
		return cgroup2.NewManager("/sys/fs/cgroup", group, resources)
	}
	pluginCgroupNow     = time.Now
	pluginCgroupFactory = newPluginCgroup
)

func (c *managedPluginCgroup) AddProc(pid uint64) error {
	return c.manager.AddProc(pid)
}

func (c *managedPluginCgroup) Kill() error {
	return c.manager.Kill()
}

func (c *managedPluginCgroup) Delete() error {
	return c.manager.Delete()
}

func (c *managedPluginCgroup) Path() string {
	return c.path
}

func newPluginCgroup(namespace string) (pluginCgroup, error) {
	mode := pluginCgroupsMode()
	if mode != cgroups.Unified {
		return nil, fmt.Errorf("plugin cgroup requires unified cgroup v2 mode, got %s", pluginCgroupModeString(mode))
	}

	groupName := filepath.Join(pluginCgroupPrefix, pluginCgroupLeaf(namespace))
	groupPath, err := pluginCgroupNestedGroupPath(groupName)
	if err != nil {
		return nil, fmt.Errorf("build plugin cgroup path for %q: %w", namespace, err)
	}

	manager, err := pluginCgroupNewManager(groupPath, &cgroup2.Resources{})
	if err != nil {
		return nil, fmt.Errorf("create plugin cgroup %q: %w", groupPath, err)
	}

	return &managedPluginCgroup{
		manager: manager,
		path:    groupPath,
	}, nil
}

func pluginCgroupLeaf(namespace string) string {
	sanitized := sanitizePluginCgroupComponent(namespace)
	return fmt.Sprintf("%s-%d-%d", sanitized, os.Getpid(), pluginCgroupNow().UnixNano())
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
	_ = cgroup.Kill()
	_ = cgroup.Delete()
}
