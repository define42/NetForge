//go:build linux

package main

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	pathpkg "path"
	"sort"
	"strings"
	"time"

	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"
)

const (
	defaultSFTPPort          = "22"
	maxSFTPTransferBytes     = 32 << 20
	namespaceSFTPDialTimeout = 5 * time.Second
)

type namespaceSFTPFile interface {
	io.Reader
	io.Writer
	io.Closer
	Stat() (os.FileInfo, error)
}

type namespaceSFTPClient interface {
	ReadDir(string) ([]os.FileInfo, error)
	Open(string) (namespaceSFTPFile, error)
	OpenFile(string, int) (namespaceSFTPFile, error)
	MkdirAll(string) error
	Chmod(string, os.FileMode) error
	Lstat(string) (os.FileInfo, error)
	Remove(string) error
	RemoveDirectory(string) error
	Close() error
}

type sshSFTPClient struct {
	client    *sftp.Client
	sshClient *ssh.Client
}

func (c *sshSFTPClient) ReadDir(path string) ([]os.FileInfo, error) {
	return c.client.ReadDir(path)
}

func (c *sshSFTPClient) Open(path string) (namespaceSFTPFile, error) {
	return c.client.Open(path)
}

func (c *sshSFTPClient) OpenFile(path string, flags int) (namespaceSFTPFile, error) {
	return c.client.OpenFile(path, flags)
}

func (c *sshSFTPClient) MkdirAll(path string) error {
	return c.client.MkdirAll(path)
}

func (c *sshSFTPClient) Chmod(path string, mode os.FileMode) error {
	return c.client.Chmod(path, mode)
}

func (c *sshSFTPClient) Lstat(path string) (os.FileInfo, error) {
	return c.client.Lstat(path)
}

func (c *sshSFTPClient) Remove(path string) error {
	return c.client.Remove(path)
}

func (c *sshSFTPClient) RemoveDirectory(path string) error {
	return c.client.RemoveDirectory(path)
}

func (c *sshSFTPClient) Close() error {
	return errors.Join(c.client.Close(), c.sshClient.Close())
}

var openNamespaceSFTPClient = func(connInfo SFTPConnectionInfo) (namespaceSFTPClient, error) {
	address, config, err := buildNamespaceSFTPClientConfig(connInfo)
	if err != nil {
		return nil, err
	}

	sshClient, err := ssh.Dial("tcp", address, config)
	if err != nil {
		return nil, fmt.Errorf("dial sftp ssh server %s: %w", address, err)
	}

	sftpClient, err := sftp.NewClient(sshClient)
	if err != nil {
		_ = sshClient.Close()
		return nil, fmt.Errorf("create sftp client for %s: %w", address, err)
	}

	return &sshSFTPClient{client: sftpClient, sshClient: sshClient}, nil
}

func (s *namespaceHTTPService) SFTPList(req SFTPListRequest) (*SFTPListResponse, error) {
	resp, err := listNamespaceSFTP(req)
	if err != nil {
		return nil, fmt.Errorf("sftp list from %s failed: %w", s.cfg.Namespace, err)
	}
	return resp, nil
}

func (s *namespaceHTTPService) SFTPFetch(req SFTPFetchRequest) (*SFTPFetchResponse, error) {
	resp, err := fetchNamespaceSFTP(req)
	if err != nil {
		return nil, fmt.Errorf("sftp fetch from %s failed: %w", s.cfg.Namespace, err)
	}
	return resp, nil
}

func (s *namespaceHTTPService) SFTPPush(req SFTPPushRequest) (*SFTPPushResponse, error) {
	resp, err := pushNamespaceSFTP(req)
	if err != nil {
		return nil, fmt.Errorf("sftp push from %s failed: %w", s.cfg.Namespace, err)
	}
	return resp, nil
}

func (s *namespaceHTTPService) SFTPDelete(req SFTPDeleteRequest) (*SFTPDeleteResponse, error) {
	resp, err := deleteNamespaceSFTP(req)
	if err != nil {
		return nil, fmt.Errorf("sftp delete from %s failed: %w", s.cfg.Namespace, err)
	}
	return resp, nil
}

func listNamespaceSFTP(req SFTPListRequest) (*SFTPListResponse, error) {
	directory := normalizeSFTPDirectory(req.Directory)
	client, err := openNamespaceSFTPClient(req.Connection)
	if err != nil {
		return nil, err
	}
	defer client.Close()

	entries, err := client.ReadDir(directory)
	if err != nil {
		return nil, fmt.Errorf("read remote directory %q: %w", directory, err)
	}

	sort.Slice(entries, func(i, j int) bool {
		return entries[i].Name() < entries[j].Name()
	})

	resp := &SFTPListResponse{Entries: make([]SFTPEntry, 0, len(entries))}
	for _, entry := range entries {
		resp.Entries = append(resp.Entries, SFTPEntry{
			Name:        entry.Name(),
			Path:        joinSFTPPath(directory, entry.Name()),
			Size:        entry.Size(),
			Mode:        uint32(entry.Mode()),
			IsDir:       entry.IsDir(),
			ModTimeUnix: entry.ModTime().Unix(),
		})
	}
	return resp, nil
}

func fetchNamespaceSFTP(req SFTPFetchRequest) (*SFTPFetchResponse, error) {
	remotePath, err := requireSFTPPath(req.Path)
	if err != nil {
		return nil, err
	}

	client, err := openNamespaceSFTPClient(req.Connection)
	if err != nil {
		return nil, err
	}
	defer client.Close()

	file, err := client.Open(remotePath)
	if err != nil {
		return nil, fmt.Errorf("open remote file %q: %w", remotePath, err)
	}
	defer file.Close()

	info, err := file.Stat()
	if err != nil {
		return nil, fmt.Errorf("stat remote file %q: %w", remotePath, err)
	}
	if info.Size() > maxSFTPTransferBytes {
		return nil, fmt.Errorf("remote file %q exceeds %d byte limit", remotePath, maxSFTPTransferBytes)
	}

	data, err := io.ReadAll(io.LimitReader(file, maxSFTPTransferBytes+1))
	if err != nil {
		return nil, fmt.Errorf("read remote file %q: %w", remotePath, err)
	}
	if int64(len(data)) > maxSFTPTransferBytes {
		return nil, fmt.Errorf("remote file %q exceeds %d byte limit", remotePath, maxSFTPTransferBytes)
	}

	return &SFTPFetchResponse{
		Path:        remotePath,
		Data:        data,
		Size:        int64(len(data)),
		Mode:        uint32(info.Mode()),
		ModTimeUnix: info.ModTime().Unix(),
	}, nil
}

func pushNamespaceSFTP(req SFTPPushRequest) (*SFTPPushResponse, error) {
	remotePath, err := requireSFTPPath(req.Path)
	if err != nil {
		return nil, err
	}
	if int64(len(req.Data)) > maxSFTPTransferBytes {
		return nil, fmt.Errorf("push payload exceeds %d byte limit", maxSFTPTransferBytes)
	}

	client, err := openNamespaceSFTPClient(req.Connection)
	if err != nil {
		return nil, err
	}
	defer client.Close()

	if req.CreateParents {
		parent := pathpkg.Dir(remotePath)
		if parent != "." {
			if err := client.MkdirAll(parent); err != nil {
				return nil, fmt.Errorf("create remote parent directories for %q: %w", remotePath, err)
			}
		}
	}

	file, err := client.OpenFile(remotePath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC)
	if err != nil {
		return nil, fmt.Errorf("open remote file %q for write: %w", remotePath, err)
	}

	written, writeErr := file.Write(req.Data)
	closeErr := file.Close()
	if writeErr != nil {
		return nil, fmt.Errorf("write remote file %q: %w", remotePath, writeErr)
	}
	if written != len(req.Data) {
		return nil, fmt.Errorf("write remote file %q: short write %d/%d", remotePath, written, len(req.Data))
	}
	if closeErr != nil {
		return nil, fmt.Errorf("close remote file %q after write: %w", remotePath, closeErr)
	}

	if req.Mode != 0 {
		if err := client.Chmod(remotePath, os.FileMode(req.Mode)); err != nil {
			return nil, fmt.Errorf("chmod remote file %q: %w", remotePath, err)
		}
	}

	return &SFTPPushResponse{
		Path:         remotePath,
		BytesWritten: int64(written),
	}, nil
}

func deleteNamespaceSFTP(req SFTPDeleteRequest) (*SFTPDeleteResponse, error) {
	remotePath, err := requireSFTPPath(req.Path)
	if err != nil {
		return nil, err
	}

	client, err := openNamespaceSFTPClient(req.Connection)
	if err != nil {
		return nil, err
	}
	defer client.Close()

	if err := deleteNamespaceSFTPPath(client, remotePath, req.Recursive); err != nil {
		return nil, err
	}

	return &SFTPDeleteResponse{
		Path:    remotePath,
		Removed: true,
	}, nil
}

func deleteNamespaceSFTPPath(client namespaceSFTPClient, remotePath string, recursive bool) error {
	info, err := client.Lstat(remotePath)
	if err != nil {
		return fmt.Errorf("stat remote path %q: %w", remotePath, err)
	}

	if info.IsDir() {
		if !recursive {
			if err := client.RemoveDirectory(remotePath); err != nil {
				return fmt.Errorf("remove remote directory %q: %w", remotePath, err)
			}
			return nil
		}

		entries, err := client.ReadDir(remotePath)
		if err != nil {
			return fmt.Errorf("read remote directory %q for delete: %w", remotePath, err)
		}
		for _, entry := range entries {
			childPath := joinSFTPPath(remotePath, entry.Name())
			if err := deleteNamespaceSFTPPath(client, childPath, true); err != nil {
				return err
			}
		}
		if err := client.RemoveDirectory(remotePath); err != nil {
			return fmt.Errorf("remove remote directory %q: %w", remotePath, err)
		}
		return nil
	}

	if err := client.Remove(remotePath); err != nil {
		return fmt.Errorf("remove remote file %q: %w", remotePath, err)
	}
	return nil
}

func buildNamespaceSFTPClientConfig(connInfo SFTPConnectionInfo) (string, *ssh.ClientConfig, error) {
	address, err := normalizeSFTPAddress(connInfo.Address)
	if err != nil {
		return "", nil, err
	}

	username := strings.TrimSpace(connInfo.Username)
	if username == "" {
		return "", nil, errors.New("sftp username is required")
	}

	authMethods, err := buildNamespaceSFTPAuthMethods(connInfo)
	if err != nil {
		return "", nil, err
	}

	hostKeyCallback, err := buildNamespaceSFTPHostKeyCallback(connInfo)
	if err != nil {
		return "", nil, err
	}

	return address, &ssh.ClientConfig{
		User:            username,
		Auth:            authMethods,
		HostKeyCallback: hostKeyCallback,
		Timeout:         namespaceSFTPDialTimeout,
	}, nil
}

func buildNamespaceSFTPAuthMethods(connInfo SFTPConnectionInfo) ([]ssh.AuthMethod, error) {
	methods := make([]ssh.AuthMethod, 0, 2)

	if password := connInfo.Password; password != "" {
		methods = append(methods, ssh.Password(password))
	}

	if privateKey := strings.TrimSpace(connInfo.PrivateKeyPEM); privateKey != "" {
		signer, err := ssh.ParsePrivateKey([]byte(privateKey))
		if err != nil {
			return nil, fmt.Errorf("parse sftp private key: %w", err)
		}
		methods = append(methods, ssh.PublicKeys(signer))
	}

	if len(methods) == 0 {
		return nil, errors.New("sftp password or private key is required")
	}
	return methods, nil
}

func buildNamespaceSFTPHostKeyCallback(connInfo SFTPConnectionInfo) (ssh.HostKeyCallback, error) {
	if connInfo.InsecureIgnoreHostKey {
		return ssh.InsecureIgnoreHostKey(), nil
	}

	hostPublicKey := strings.TrimSpace(connInfo.HostPublicKey)
	if hostPublicKey == "" {
		return nil, errors.New("sftp host public key is required unless insecure_ignore_host_key is set")
	}

	expectedKey, _, _, _, err := ssh.ParseAuthorizedKey([]byte(hostPublicKey))
	if err != nil {
		return nil, fmt.Errorf("parse sftp host public key: %w", err)
	}

	return func(hostname string, _ net.Addr, actualKey ssh.PublicKey) error {
		if !bytes.Equal(actualKey.Marshal(), expectedKey.Marshal()) {
			return fmt.Errorf("unexpected sftp host key for %s", hostname)
		}
		return nil
	}, nil
}

func normalizeSFTPAddress(address string) (string, error) {
	trimmed := strings.TrimSpace(address)
	if trimmed == "" {
		return "", errors.New("sftp address is required")
	}

	host, port, err := net.SplitHostPort(trimmed)
	if err == nil {
		if host == "" || port == "" {
			return "", fmt.Errorf("invalid sftp address %q", address)
		}
		return trimmed, nil
	}

	if net.ParseIP(trimmed) != nil {
		return net.JoinHostPort(trimmed, defaultSFTPPort), nil
	}

	if strings.Contains(err.Error(), "missing port in address") {
		return net.JoinHostPort(trimmed, defaultSFTPPort), nil
	}

	return "", fmt.Errorf("invalid sftp address %q: %w", address, err)
}

func normalizeSFTPDirectory(directory string) string {
	trimmed := strings.TrimSpace(directory)
	if trimmed == "" {
		return "."
	}
	return pathpkg.Clean(trimmed)
}

func requireSFTPPath(path string) (string, error) {
	trimmed := strings.TrimSpace(path)
	if trimmed == "" {
		return "", errors.New("sftp path is required")
	}
	return pathpkg.Clean(trimmed), nil
}

func joinSFTPPath(parent, name string) string {
	if parent == "." {
		return pathpkg.Clean(name)
	}
	return pathpkg.Join(parent, name)
}
