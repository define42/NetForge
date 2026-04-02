//go:build linux

package main

import (
	"errors"
	"fmt"
	"os"
	"syscall"
)

const (
	defaultPluginRuntimeBase = "/var/lib/netforge"
	pluginRuntimeDirMode     = 0o700
)

func ensurePrivateOwnedDir(path string) error {
	if path == "" {
		return errors.New("runtime dir path must not be empty")
	}

	info, err := os.Lstat(path)
	if err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("stat runtime dir %q: %w", path, err)
		}
		if err := os.MkdirAll(path, pluginRuntimeDirMode); err != nil {
			return fmt.Errorf("create runtime dir %q: %w", path, err)
		}
		info, err = os.Lstat(path)
		if err != nil {
			return fmt.Errorf("re-stat runtime dir %q: %w", path, err)
		}
	}

	if info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("runtime dir %q must not be a symlink", path)
	}
	if !info.IsDir() {
		return fmt.Errorf("runtime dir %q is not a directory", path)
	}

	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return fmt.Errorf("runtime dir %q does not expose unix ownership metadata", path)
	}
	wantUID := uint32(os.Geteuid())
	if stat.Uid != wantUID {
		return fmt.Errorf("runtime dir %q owned by uid %d, want %d", path, stat.Uid, wantUID)
	}

	if info.Mode().Perm() != pluginRuntimeDirMode {
		if err := os.Chmod(path, pluginRuntimeDirMode); err != nil {
			return fmt.Errorf("chmod runtime dir %q to %#o: %w", path, pluginRuntimeDirMode, err)
		}
	}

	return nil
}
