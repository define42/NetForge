//go:build linux

package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"io"
	"os"
	pathpkg "path"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
)

type localSFTPClient struct {
	root string
}

func (c *localSFTPClient) ReadDir(remotePath string) ([]os.FileInfo, error) {
	localPath, err := c.resolve(remotePath)
	if err != nil {
		return nil, err
	}

	entries, err := os.ReadDir(localPath)
	if err != nil {
		return nil, err
	}

	info := make([]os.FileInfo, 0, len(entries))
	for _, entry := range entries {
		entryInfo, err := entry.Info()
		if err != nil {
			return nil, err
		}
		info = append(info, entryInfo)
	}
	return info, nil
}

func (c *localSFTPClient) Open(remotePath string) (namespaceSFTPFile, error) {
	localPath, err := c.resolve(remotePath)
	if err != nil {
		return nil, err
	}
	return os.Open(localPath)
}

func (c *localSFTPClient) OpenFile(remotePath string, flags int) (namespaceSFTPFile, error) {
	localPath, err := c.resolve(remotePath)
	if err != nil {
		return nil, err
	}
	return os.OpenFile(localPath, flags, 0o644)
}

func (c *localSFTPClient) MkdirAll(remotePath string) error {
	localPath, err := c.resolve(remotePath)
	if err != nil {
		return err
	}
	return os.MkdirAll(localPath, 0o755)
}

func (c *localSFTPClient) Chmod(remotePath string, mode os.FileMode) error {
	localPath, err := c.resolve(remotePath)
	if err != nil {
		return err
	}
	return os.Chmod(localPath, mode)
}

func (c *localSFTPClient) Lstat(remotePath string) (os.FileInfo, error) {
	localPath, err := c.resolve(remotePath)
	if err != nil {
		return nil, err
	}
	return os.Lstat(localPath)
}

func (c *localSFTPClient) Remove(remotePath string) error {
	localPath, err := c.resolve(remotePath)
	if err != nil {
		return err
	}
	return os.Remove(localPath)
}

func (c *localSFTPClient) RemoveDirectory(remotePath string) error {
	localPath, err := c.resolve(remotePath)
	if err != nil {
		return err
	}
	return os.Remove(localPath)
}

func (c *localSFTPClient) Close() error {
	return nil
}

func (c *localSFTPClient) resolve(remotePath string) (string, error) {
	clean := pathpkg.Clean("/" + strings.TrimSpace(remotePath))
	localPath := filepath.Join(c.root, filepath.FromSlash(strings.TrimPrefix(clean, "/")))
	return localPath, nil
}

func withLocalSFTPClientFactory(t *testing.T, root string) {
	t.Helper()

	original := openNamespaceSFTPClient
	openNamespaceSFTPClient = func(SFTPConnectionInfo) (namespaceSFTPClient, error) {
		return &localSFTPClient{root: root}, nil
	}
	t.Cleanup(func() {
		openNamespaceSFTPClient = original
	})
}

func testSFTPConnectionInfo() SFTPConnectionInfo {
	return SFTPConnectionInfo{
		Address:               "127.0.0.1",
		Username:              "demo",
		Password:              "secret",
		InsecureIgnoreHostKey: true,
	}
}

func TestBuildNamespaceSFTPClientConfig(t *testing.T) {
	hostKey := mustAuthorizedPublicKey(t)

	address, cfg, err := buildNamespaceSFTPClientConfig(SFTPConnectionInfo{
		Address:       "sftp.example.com",
		Username:      "demo",
		Password:      "secret",
		HostPublicKey: hostKey,
	})
	if err != nil {
		t.Fatalf("buildNamespaceSFTPClientConfig failed: %v", err)
	}
	if address != "sftp.example.com:22" {
		t.Fatalf("unexpected address: got %q want %q", address, "sftp.example.com:22")
	}
	if cfg.User != "demo" {
		t.Fatalf("unexpected user: got %q want %q", cfg.User, "demo")
	}
	if len(cfg.Auth) != 1 {
		t.Fatalf("unexpected auth method count: got %d want %d", len(cfg.Auth), 1)
	}

	t.Run("requires host key or insecure flag", func(t *testing.T) {
		_, _, err := buildNamespaceSFTPClientConfig(SFTPConnectionInfo{
			Address:  "127.0.0.1:22",
			Username: "demo",
			Password: "secret",
		})
		if err == nil || !strings.Contains(err.Error(), "host public key is required") {
			t.Fatalf("unexpected error: %v", err)
		}
	})

	t.Run("requires auth", func(t *testing.T) {
		_, _, err := buildNamespaceSFTPClientConfig(SFTPConnectionInfo{
			Address:               "127.0.0.1:22",
			Username:              "demo",
			InsecureIgnoreHostKey: true,
		})
		if err == nil || !strings.Contains(err.Error(), "password or private key is required") {
			t.Fatalf("unexpected error: %v", err)
		}
	})

	t.Run("invalid address", func(t *testing.T) {
		_, _, err := buildNamespaceSFTPClientConfig(SFTPConnectionInfo{
			Address:               "host:",
			Username:              "demo",
			Password:              "secret",
			InsecureIgnoreHostKey: true,
		})
		if err == nil {
			t.Fatal("expected invalid address error")
		}
	})
}

func TestNamespaceHTTPServiceSFTPOperations(t *testing.T) {
	root := t.TempDir()
	withLocalSFTPClientFactory(t, root)

	if err := os.MkdirAll(filepath.Join(root, "existing"), 0o755); err != nil {
		t.Fatalf("MkdirAll existing failed: %v", err)
	}
	if err := os.WriteFile(filepath.Join(root, "existing", "alpha.txt"), []byte("alpha"), 0o640); err != nil {
		t.Fatalf("WriteFile alpha failed: %v", err)
	}

	svc := &namespaceHTTPService{cfg: PluginConfig{Namespace: "ns-sftp"}}
	conn := testSFTPConnectionInfo()

	listResp, err := svc.SFTPList(SFTPListRequest{
		Connection: conn,
		Directory:  "/existing",
	})
	if err != nil {
		t.Fatalf("SFTPList failed: %v", err)
	}
	if len(listResp.Entries) != 1 {
		t.Fatalf("unexpected SFTPList entry count: %+v", listResp.Entries)
	}
	if got := listResp.Entries[0]; got.Name != "alpha.txt" || got.Path != "/existing/alpha.txt" || got.Size != 5 || got.Mode != uint32(0o640) || got.IsDir || got.ModTimeUnix == 0 {
		t.Fatalf("unexpected SFTPList response: %+v", listResp.Entries)
	}

	pushResp, err := svc.SFTPPush(SFTPPushRequest{
		Connection:    conn,
		Path:          "/nested/upload.txt",
		Data:          []byte("payload"),
		Mode:          0o600,
		CreateParents: true,
	})
	if err != nil {
		t.Fatalf("SFTPPush failed: %v", err)
	}
	if pushResp.Path != "/nested/upload.txt" || pushResp.BytesWritten != 7 {
		t.Fatalf("unexpected SFTPPush response: %+v", pushResp)
	}

	fetchResp, err := svc.SFTPFetch(SFTPFetchRequest{
		Connection: conn,
		Path:       "/nested/upload.txt",
	})
	if err != nil {
		t.Fatalf("SFTPFetch failed: %v", err)
	}
	if fetchResp.Path != "/nested/upload.txt" || string(fetchResp.Data) != "payload" || fetchResp.Size != 7 {
		t.Fatalf("unexpected SFTPFetch response: %+v", fetchResp)
	}

	deleteResp, err := svc.SFTPDelete(SFTPDeleteRequest{
		Connection: conn,
		Path:       "/nested/upload.txt",
	})
	if err != nil {
		t.Fatalf("SFTPDelete file failed: %v", err)
	}
	if !deleteResp.Removed {
		t.Fatalf("unexpected SFTPDelete response: %+v", deleteResp)
	}

	if _, err := os.Stat(filepath.Join(root, "nested", "upload.txt")); !os.IsNotExist(err) {
		t.Fatalf("expected pushed file to be deleted, stat err = %v", err)
	}

	if err := os.MkdirAll(filepath.Join(root, "tree", "leaf"), 0o755); err != nil {
		t.Fatalf("MkdirAll tree failed: %v", err)
	}
	if err := os.WriteFile(filepath.Join(root, "tree", "leaf", "note.txt"), []byte("note"), 0o644); err != nil {
		t.Fatalf("WriteFile note failed: %v", err)
	}

	deleteResp, err = svc.SFTPDelete(SFTPDeleteRequest{
		Connection: conn,
		Path:       "/tree",
		Recursive:  true,
	})
	if err != nil {
		t.Fatalf("SFTPDelete recursive failed: %v", err)
	}
	if !deleteResp.Removed {
		t.Fatalf("unexpected recursive delete response: %+v", deleteResp)
	}
	if _, err := os.Stat(filepath.Join(root, "tree")); !os.IsNotExist(err) {
		t.Fatalf("expected tree to be removed, stat err = %v", err)
	}
}

func mustAuthorizedPublicKey(t *testing.T) string {
	t.Helper()

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("GenerateKey failed: %v", err)
	}

	signer, err := ssh.NewSignerFromKey(privateKey)
	if err != nil {
		t.Fatalf("NewSignerFromKey failed: %v", err)
	}

	return strings.TrimSpace(string(ssh.MarshalAuthorizedKey(signer.PublicKey())))
}

func TestPushNamespaceSFTPRejectsOversizedPayload(t *testing.T) {
	root := t.TempDir()
	withLocalSFTPClientFactory(t, root)

	svc := &namespaceHTTPService{cfg: PluginConfig{Namespace: "ns-sftp"}}
	_, err := svc.SFTPPush(SFTPPushRequest{
		Connection:    testSFTPConnectionInfo(),
		Path:          "/big.bin",
		Data:          make([]byte, maxSFTPTransferBytes+1),
		CreateParents: true,
	})
	if err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestFetchNamespaceSFTPRejectsOversizedFile(t *testing.T) {
	root := t.TempDir()
	withLocalSFTPClientFactory(t, root)

	largePath := filepath.Join(root, "large.bin")
	file, err := os.Create(largePath)
	if err != nil {
		t.Fatalf("Create large.bin failed: %v", err)
	}
	if _, err := file.Write(make([]byte, maxSFTPTransferBytes+1)); err != nil {
		_ = file.Close()
		t.Fatalf("Write large.bin failed: %v", err)
	}
	if err := file.Close(); err != nil {
		t.Fatalf("Close large.bin failed: %v", err)
	}

	svc := &namespaceHTTPService{cfg: PluginConfig{Namespace: "ns-sftp"}}
	_, err = svc.SFTPFetch(SFTPFetchRequest{
		Connection: testSFTPConnectionInfo(),
		Path:       "/large.bin",
	})
	if err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestDeleteNamespaceSFTPRejectsEmptyPath(t *testing.T) {
	root := t.TempDir()
	withLocalSFTPClientFactory(t, root)

	svc := &namespaceHTTPService{cfg: PluginConfig{Namespace: "ns-sftp"}}
	_, err := svc.SFTPDelete(SFTPDeleteRequest{
		Connection: testSFTPConnectionInfo(),
		Path:       "   ",
	})
	if err == nil || !strings.Contains(err.Error(), "path is required") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestBuildNamespaceSFTPClientConfigWithPrivateKey(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("GenerateKey failed: %v", err)
	}
	privateKeyDER := x509.MarshalPKCS1PrivateKey(privateKey)
	privateKeyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: privateKeyDER})

	_, cfg, err := buildNamespaceSFTPClientConfig(SFTPConnectionInfo{
		Address:               "127.0.0.1:22",
		Username:              "demo",
		PrivateKeyPEM:         string(privateKeyPEM),
		InsecureIgnoreHostKey: true,
	})
	if err != nil {
		t.Fatalf("buildNamespaceSFTPClientConfig failed: %v", err)
	}
	if len(cfg.Auth) != 1 {
		t.Fatalf("unexpected auth method count: got %d want %d", len(cfg.Auth), 1)
	}
}

func TestFetchNamespaceSFTPReadsExpectedContent(t *testing.T) {
	root := t.TempDir()
	withLocalSFTPClientFactory(t, root)

	if err := os.WriteFile(filepath.Join(root, "demo.txt"), []byte("hello"), 0o644); err != nil {
		t.Fatalf("WriteFile demo.txt failed: %v", err)
	}

	resp, err := fetchNamespaceSFTP(SFTPFetchRequest{
		Connection: testSFTPConnectionInfo(),
		Path:       "/demo.txt",
	})
	if err != nil {
		t.Fatalf("fetchNamespaceSFTP failed: %v", err)
	}
	if string(resp.Data) != "hello" {
		t.Fatalf("unexpected file content: %q", string(resp.Data))
	}
}

func TestListNamespaceSFTPDefaultsToCurrentDirectory(t *testing.T) {
	root := t.TempDir()
	withLocalSFTPClientFactory(t, root)

	if err := os.WriteFile(filepath.Join(root, "alpha.txt"), []byte("alpha"), 0o644); err != nil {
		t.Fatalf("WriteFile alpha.txt failed: %v", err)
	}

	resp, err := listNamespaceSFTP(SFTPListRequest{Connection: testSFTPConnectionInfo()})
	if err != nil {
		t.Fatalf("listNamespaceSFTP failed: %v", err)
	}
	if len(resp.Entries) != 1 || resp.Entries[0].Path != "alpha.txt" {
		t.Fatalf("unexpected entries: %+v", resp.Entries)
	}
}

func TestPushNamespaceSFTPWritesContent(t *testing.T) {
	root := t.TempDir()
	withLocalSFTPClientFactory(t, root)

	resp, err := pushNamespaceSFTP(SFTPPushRequest{
		Connection:    testSFTPConnectionInfo(),
		Path:          "/dir/data.txt",
		Data:          []byte("hello"),
		CreateParents: true,
	})
	if err != nil {
		t.Fatalf("pushNamespaceSFTP failed: %v", err)
	}
	if resp.BytesWritten != 5 {
		t.Fatalf("unexpected bytes written: %+v", resp)
	}

	file, err := os.Open(filepath.Join(root, "dir", "data.txt"))
	if err != nil {
		t.Fatalf("Open written file failed: %v", err)
	}
	defer file.Close()
	data, err := io.ReadAll(file)
	if err != nil {
		t.Fatalf("ReadAll written file failed: %v", err)
	}
	if string(data) != "hello" {
		t.Fatalf("unexpected written data: %q", string(data))
	}
}
