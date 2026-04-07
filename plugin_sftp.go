//go:build linux

package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"path/filepath"
	"strings"

	sftpserverpkg "github.com/define42/NetForge/internal/sftpserver"
	"golang.org/x/crypto/ssh"
)

const (
	pluginSFTPPort            = 2222
	pluginSFTPHostKeyFilename = "sftp-host-key.pem"
	pluginSFTPBindHost        = "0.0.0.0"
)

type sftpServerLifecycle interface {
	Serve(net.Listener) error
	Close() error
	ListeningAddr() net.Addr
	AddUser(string, sftpserverpkg.UserInfo)
	RemoveUser(string)
}

var loadNamespaceSFTPHostSigner = func() (ssh.Signer, error) {
	return ensureNamespaceSFTPHostSigner(filepath.Join(pluginSandboxDataDir, pluginSFTPHostKeyFilename))
}

var newNamespaceSFTPServer = func(addr string, users map[string]sftpserverpkg.UserInfo, signer ssh.Signer) sftpServerLifecycle {
	return sftpserverpkg.NewServer(addr, users, signer)
}

var validateNamespaceSFTPUserRoot = func(root string) error {
	dataRoot := filepath.Clean(pluginSandboxDataDir)
	if root != dataRoot && !strings.HasPrefix(root, dataRoot+string(os.PathSeparator)) {
		return fmt.Errorf("sftp root %q must stay under %q", root, dataRoot)
	}
	return nil
}

var createNamespaceSFTPUserRoot = func(root string) error {
	if err := os.MkdirAll(root, pluginRuntimeDirMode); err != nil {
		return fmt.Errorf("create sftp user root %q: %w", root, err)
	}
	if err := os.Chmod(root, pluginRuntimeDirMode); err != nil {
		return fmt.Errorf("chmod sftp user root %q: %w", root, err)
	}
	return nil
}

func (s *namespaceHTTPService) StartSFTP(port int) (*StartSFTPResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.sftpServer != nil {
		if s.sftpPort != port {
			return nil, fmt.Errorf("sftp server already running on port %d", s.sftpPort)
		}
		return &StartSFTPResponse{SFTPAddr: s.sftpAddr}, nil
	}

	signer, err := loadNamespaceSFTPHostSigner()
	if err != nil {
		return nil, err
	}

	addr := pluginSFTPBindAddress(port)
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, err
	}

	server := newNamespaceSFTPServer(addr, s.namespaceSFTPUsersLocked(), signer)
	s.sftpServer = server
	s.sftpPort = port
	s.sftpAddr = addr

	go func(namespace string, srv sftpServerLifecycle, listener net.Listener) {
		if err := srv.Serve(listener); err != nil {
			log.Printf("namespace=%s sftp server error: %v", namespace, err)
		}
	}(s.cfg.Namespace, server, ln)

	return &StartSFTPResponse{SFTPAddr: s.sftpAddr}, nil
}

func pluginSFTPBindAddress(port int) string {
	return fmt.Sprintf("%s:%d", pluginSFTPBindHost, port)
}

func (s *namespaceHTTPService) StopSFTP() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.sftpServer == nil {
		return nil
	}

	err := s.sftpServer.Close()
	s.sftpServer = nil
	s.sftpAddr = ""
	s.sftpPort = 0
	return err
}

func (s *namespaceHTTPService) EnsureNamespaceSFTPUser(req EnsureNamespaceSFTPUserRequest) (*NamespaceSFTPUserStatusResponse, error) {
	req, err := normalizeNamespaceSFTPUserRequest(req)
	if err != nil {
		return nil, err
	}
	if err := createNamespaceSFTPUserRoot(req.Root); err != nil {
		return nil, err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if s.sftpUsers == nil {
		s.sftpUsers = make(map[string]EnsureNamespaceSFTPUserRequest)
	}
	s.sftpUsers[req.Username] = req
	if s.sftpServer != nil {
		s.sftpServer.AddUser(req.Username, namespaceSFTPUserInfo(req))
	}
	return namespaceSFTPUserStatusResponse(req), nil
}

func (s *namespaceHTTPService) RemoveNamespaceSFTPUser(req RemoveNamespaceSFTPUserRequest) (*NamespaceSFTPUserStatusResponse, error) {
	username := strings.TrimSpace(req.Username)
	if username == "" {
		return nil, errors.New("sftp username is required")
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if s.sftpUsers != nil {
		delete(s.sftpUsers, username)
	}
	if s.sftpServer != nil {
		s.sftpServer.RemoveUser(username)
	}
	return &NamespaceSFTPUserStatusResponse{Username: username}, nil
}

func (s *namespaceHTTPService) GetNamespaceSFTPUserStatus(req NamespaceSFTPUserStatusRequest) (*NamespaceSFTPUserStatusResponse, error) {
	username := strings.TrimSpace(req.Username)
	if username == "" {
		return nil, errors.New("sftp username is required")
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if s.sftpUsers == nil {
		return &NamespaceSFTPUserStatusResponse{Username: username}, nil
	}
	stored, ok := s.sftpUsers[username]
	if !ok {
		return &NamespaceSFTPUserStatusResponse{Username: username}, nil
	}
	return namespaceSFTPUserStatusResponse(stored), nil
}

func (s *namespaceHTTPService) namespaceSFTPUsersLocked() map[string]sftpserverpkg.UserInfo {
	if len(s.sftpUsers) == 0 {
		return map[string]sftpserverpkg.UserInfo{}
	}

	users := make(map[string]sftpserverpkg.UserInfo, len(s.sftpUsers))
	for username, req := range s.sftpUsers {
		users[username] = namespaceSFTPUserInfo(req)
	}
	return users
}

func normalizeNamespaceSFTPUserRequest(req EnsureNamespaceSFTPUserRequest) (EnsureNamespaceSFTPUserRequest, error) {
	req.Username = strings.TrimSpace(req.Username)
	req.Root = filepath.Clean(strings.TrimSpace(req.Root))
	if req.Username == "" {
		return EnsureNamespaceSFTPUserRequest{}, errors.New("sftp username is required")
	}
	if req.Password == "" {
		return EnsureNamespaceSFTPUserRequest{}, errors.New("sftp password is required")
	}
	if req.Root == "." || req.Root == "" {
		return EnsureNamespaceSFTPUserRequest{}, errors.New("sftp root is required")
	}
	if !filepath.IsAbs(req.Root) {
		return EnsureNamespaceSFTPUserRequest{}, fmt.Errorf("sftp root %q must be absolute", req.Root)
	}
	if err := validateNamespaceSFTPUserRoot(req.Root); err != nil {
		return EnsureNamespaceSFTPUserRequest{}, err
	}
	if !req.CanRead && !req.CanWrite {
		return EnsureNamespaceSFTPUserRequest{}, errors.New("sftp user must allow read or write access")
	}
	return req, nil
}

func namespaceSFTPUserInfo(req EnsureNamespaceSFTPUserRequest) sftpserverpkg.UserInfo {
	return sftpserverpkg.UserInfo{
		Password: req.Password,
		Root:     req.Root,
		CanRead:  req.CanRead,
		CanWrite: req.CanWrite,
	}
}

func namespaceSFTPUserStatusResponse(req EnsureNamespaceSFTPUserRequest) *NamespaceSFTPUserStatusResponse {
	return &NamespaceSFTPUserStatusResponse{
		Username: req.Username,
		Exists:   true,
		Root:     req.Root,
		CanRead:  req.CanRead,
		CanWrite: req.CanWrite,
	}
}

func ensureNamespaceSFTPHostSigner(path string) (ssh.Signer, error) {
	signer, err := sftpserverpkg.NewSignerFromFile(path)
	if err == nil {
		return signer, nil
	}

	var pathErr *os.PathError
	if !errors.As(err, &pathErr) || !errors.Is(pathErr.Err, os.ErrNotExist) {
		return nil, err
	}

	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, fmt.Errorf("create sftp host key dir %q: %w", filepath.Dir(path), err)
	}

	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate sftp host key: %w", err)
	}

	privateKeyDER, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		return nil, fmt.Errorf("marshal sftp host key: %w", err)
	}

	privateKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: privateKeyDER,
	})

	tmpPath := path + ".tmp"
	if err := os.WriteFile(tmpPath, privateKeyPEM, 0o600); err != nil {
		return nil, fmt.Errorf("write sftp host key %q: %w", tmpPath, err)
	}
	if err := os.Rename(tmpPath, path); err != nil {
		_ = os.Remove(tmpPath)
		return nil, fmt.Errorf("install sftp host key %q: %w", path, err)
	}

	signer, err = sftpserverpkg.NewSignerFromFile(path)
	if err != nil {
		return nil, err
	}
	return signer, nil
}
