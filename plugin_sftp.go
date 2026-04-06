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

	sftpserverpkg "github.com/define42/NetForge/internal/sftpserver"
	"golang.org/x/crypto/ssh"
)

const (
	pluginSFTPPort            = 2222
	pluginSFTPHostKeyFilename = "sftp-host-key.pem"
)

type sftpServerLifecycle interface {
	Serve(net.Listener) error
	Close() error
	ListeningAddr() net.Addr
}

var loadNamespaceSFTPHostSigner = func() (ssh.Signer, error) {
	return ensureNamespaceSFTPHostSigner(filepath.Join(pluginSandboxDataDir, pluginSFTPHostKeyFilename))
}

var newNamespaceSFTPServer = func(addr string, signer ssh.Signer) sftpServerLifecycle {
	return sftpserverpkg.NewServer(addr, map[string]sftpserverpkg.UserInfo{}, signer)
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

	addr := fmt.Sprintf(":%d", port)
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, err
	}

	server := newNamespaceSFTPServer(addr, signer)
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
