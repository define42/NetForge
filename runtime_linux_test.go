//go:build linux

package main

import (
	"os"
	"path/filepath"
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
