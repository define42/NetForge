//go:build linux

package main

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

func TestEnsurePrivateOwnedDir(t *testing.T) {
	t.Run("creates missing dir with private mode", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "runtime")
		if err := ensurePrivateOwnedDir(path); err != nil {
			t.Fatalf("ensurePrivateOwnedDir failed: %v", err)
		}

		info, err := os.Stat(path)
		if err != nil {
			t.Fatalf("stat runtime dir failed: %v", err)
		}
		if !info.IsDir() {
			t.Fatalf("runtime path is not a directory: mode=%v", info.Mode())
		}
		if got := info.Mode().Perm(); got != pluginRuntimeDirMode {
			t.Fatalf("runtime dir mode = %#o, want %#o", got, pluginRuntimeDirMode)
		}
	})

	t.Run("tightens existing dir permissions", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "runtime")
		if err := os.Mkdir(path, 0o755); err != nil {
			t.Fatalf("mkdir runtime dir failed: %v", err)
		}

		if err := ensurePrivateOwnedDir(path); err != nil {
			t.Fatalf("ensurePrivateOwnedDir failed: %v", err)
		}

		info, err := os.Stat(path)
		if err != nil {
			t.Fatalf("stat runtime dir failed: %v", err)
		}
		if got := info.Mode().Perm(); got != pluginRuntimeDirMode {
			t.Fatalf("runtime dir mode = %#o, want %#o", got, pluginRuntimeDirMode)
		}
	})

	t.Run("rejects symlink", func(t *testing.T) {
		base := t.TempDir()
		target := filepath.Join(base, "target")
		if err := os.Mkdir(target, pluginRuntimeDirMode); err != nil {
			t.Fatalf("mkdir target failed: %v", err)
		}

		link := filepath.Join(base, "runtime-link")
		if err := os.Symlink(target, link); err != nil {
			t.Fatalf("symlink runtime dir failed: %v", err)
		}

		if err := ensurePrivateOwnedDir(link); err == nil {
			t.Fatal("ensurePrivateOwnedDir succeeded for symlink, want error")
		}
	})
}

func TestPersistentPluginDataBase(t *testing.T) {
	persistentBase := "/data/netforge"
	if got := persistentPluginDataBase(persistentBase); got != "/data/netforge/plugin-data" {
		t.Fatalf("persistentPluginDataBase = %q, want %q", got, "/data/netforge/plugin-data")
	}
	if got := persistentPluginDataDir(persistentBase, "ns1"); got != "/data/netforge/plugin-data/ns1" {
		t.Fatalf("persistentPluginDataDir = %q, want %q", got, "/data/netforge/plugin-data/ns1")
	}
	if got := persistentSFTPJobsDBPath(persistentBase); got != "/data/netforge/sftp-jobs.sqlite" {
		t.Fatalf("persistentSFTPJobsDBPath = %q, want %q", got, "/data/netforge/sftp-jobs.sqlite")
	}
}

func TestEnsurePluginDataDir(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires root to chown plugin data dir")
	}

	t.Run("creates missing dir with plugin ownership", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "plugin-data")
		if err := ensurePluginDataDir(path, pluginSandboxUID, pluginSandboxGID); err != nil {
			t.Fatalf("ensurePluginDataDir failed: %v", err)
		}

		info, err := os.Stat(path)
		if err != nil {
			t.Fatalf("stat plugin data dir failed: %v", err)
		}
		if !info.IsDir() {
			t.Fatalf("plugin data path is not a directory: mode=%v", info.Mode())
		}
		if got := info.Mode().Perm(); got != pluginRuntimeDirMode {
			t.Fatalf("plugin data dir mode = %#o, want %#o", got, pluginRuntimeDirMode)
		}

		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok {
			t.Fatalf("unexpected stat type: %T", info.Sys())
		}
		if stat.Uid != pluginSandboxUID || stat.Gid != pluginSandboxGID {
			t.Fatalf("plugin data dir owner = %d:%d, want %d:%d", stat.Uid, stat.Gid, pluginSandboxUID, pluginSandboxGID)
		}
	})

	t.Run("rejects symlink", func(t *testing.T) {
		base := t.TempDir()
		target := filepath.Join(base, "target")
		if err := os.Mkdir(target, pluginRuntimeDirMode); err != nil {
			t.Fatalf("mkdir target failed: %v", err)
		}

		link := filepath.Join(base, "plugin-data-link")
		if err := os.Symlink(target, link); err != nil {
			t.Fatalf("symlink plugin data dir failed: %v", err)
		}

		if err := ensurePluginDataDir(link, pluginSandboxUID, pluginSandboxGID); err == nil {
			t.Fatal("ensurePluginDataDir succeeded for symlink, want error")
		}
	})
}
