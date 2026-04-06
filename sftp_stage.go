//go:build linux

package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log"
	"os"
	pathpkg "path"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

const (
	sftpJobStagesDirName          = "sftp-jobs"
	sftpJobIncomingDirName        = "incoming"
	sftpJobTmpDirName             = "tmp"
	sftpJobAckDirName             = "acks"
	sftpLocalStagePollInterval    = time.Second
	sftpLocalStageDefaultFileMode = 0o600
)

type sftpStageWorkerStatusState struct {
	mu            sync.Mutex
	jobID         int64
	running       bool
	lastPollAt    time.Time
	lastSuccessAt time.Time
	lastError     string
	lastFiles     int
	totalFiles    int
}

type sftpStageDownloadWorker struct {
	cancel context.CancelFunc
	token  uint64
	status *sftpStageWorkerStatusState
}

type sftpStageUploadWorker struct {
	cancel context.CancelFunc
	token  uint64
	status *sftpStageWorkerStatusState
}

type sftpLocalStageFile struct {
	RelPath string
	AbsPath string
	Mode    os.FileMode
}

type sftpBridgeCycleResult struct {
	CompletedFiles int
	CopiedFiles    int
}

func newSFTPStageWorkerStatusState(jobID int64) *sftpStageWorkerStatusState {
	return &sftpStageWorkerStatusState{jobID: jobID}
}

func (s *sftpStageWorkerStatusState) setRunning(running bool) {
	s.mu.Lock()
	s.running = running
	s.mu.Unlock()
}

func (s *sftpStageWorkerStatusState) beginCycle(now time.Time) {
	s.mu.Lock()
	s.lastPollAt = now.UTC()
	s.lastFiles = 0
	s.mu.Unlock()
}

func (s *sftpStageWorkerStatusState) finishCycle(now time.Time, files int, err error) {
	if files < 0 {
		files = 0
	}

	s.mu.Lock()
	s.lastFiles = files
	s.totalFiles += files
	if err != nil {
		s.lastError = err.Error()
		s.mu.Unlock()
		return
	}
	s.lastSuccessAt = now.UTC()
	s.lastError = ""
	s.mu.Unlock()
}

func (s *sftpStageWorkerStatusState) snapshot() SFTPStageWorkerStatus {
	s.mu.Lock()
	defer s.mu.Unlock()

	return SFTPStageWorkerStatus{
		JobID:         s.jobID,
		Running:       s.running,
		LastPollAt:    formatStoredJobTime(s.lastPollAt),
		LastSuccessAt: formatStoredJobTime(s.lastSuccessAt),
		LastError:     s.lastError,
		LastFiles:     s.lastFiles,
		TotalFiles:    s.totalFiles,
	}
}

func defaultSFTPStageWorkerStatus(jobID int64) *SFTPStageWorkerStatus {
	return &SFTPStageWorkerStatus{JobID: jobID}
}

func sftpJobStageRoot(base string, jobID int64) string {
	return filepath.Join(filepath.Clean(base), sftpJobStagesDirName, strconv.FormatInt(jobID, 10))
}

func sftpJobIncomingDir(base string, jobID int64) string {
	return filepath.Join(sftpJobStageRoot(base, jobID), sftpJobIncomingDirName)
}

func sftpJobTmpDir(base string, jobID int64) string {
	return filepath.Join(sftpJobStageRoot(base, jobID), sftpJobTmpDirName)
}

func sftpJobAckDir(base string, jobID int64) string {
	return filepath.Join(sftpJobStageRoot(base, jobID), sftpJobAckDirName)
}

func sftpStageLocalPath(root, rel string) string {
	cleanRel := filepath.Clean(filepath.FromSlash(strings.TrimSpace(rel)))
	if cleanRel == "." {
		return filepath.Clean(root)
	}
	return filepath.Join(filepath.Clean(root), cleanRel)
}

func sftpStageTempLocalPath(tmpRoot, rel string) string {
	return sftpStageLocalPath(tmpRoot, rel) + ".partial"
}

func sftpStageAckTempLocalPath(tmpRoot, rel string) string {
	return sftpStageLocalPath(filepath.Join(filepath.Clean(tmpRoot), sftpJobAckDirName), rel) + ".partial"
}

func sftpStageRelativeRemotePath(baseDir, childPath string) (string, error) {
	base := normalizeSFTPDirectory(baseDir)
	child := pathpkg.Clean(childPath)
	if child == base {
		return "", errors.New("relative remote path resolved to current directory")
	}

	if base == "." {
		return strings.TrimPrefix(child, "./"), nil
	}

	prefix := base
	if prefix != "/" {
		prefix += "/"
	}
	if !strings.HasPrefix(child, prefix) {
		return "", fmt.Errorf("remote path %q escapes base %q", childPath, baseDir)
	}
	rel := strings.TrimPrefix(child, prefix)
	if rel == "" {
		return "", errors.New("relative remote path resolved to current directory")
	}
	return rel, nil
}

func listLocalStageFiles(root string) ([]sftpLocalStageFile, error) {
	info, err := os.Stat(root)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, fmt.Errorf("stat stage root %q: %w", root, err)
	}
	if !info.IsDir() {
		return nil, fmt.Errorf("stage root %q is not a directory", root)
	}

	files := make([]sftpLocalStageFile, 0)
	err = filepath.WalkDir(root, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() {
			return nil
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		if rel == "." || strings.HasPrefix(rel, ".."+string(os.PathSeparator)) {
			return fmt.Errorf("stage file %q escapes root %q", path, root)
		}
		files = append(files, sftpLocalStageFile{
			RelPath: filepath.ToSlash(filepath.Clean(rel)),
			AbsPath: path,
			Mode:    info.Mode().Perm(),
		})
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("walk stage root %q: %w", root, err)
	}

	sort.Slice(files, func(i, j int) bool {
		return files[i].RelPath < files[j].RelPath
	})
	return files, nil
}

func listLocalAckPaths(root string) ([]string, error) {
	files, err := listLocalStageFiles(root)
	if err != nil {
		return nil, err
	}
	paths := make([]string, 0, len(files))
	for _, file := range files {
		paths = append(paths, file.RelPath)
	}
	return paths, nil
}

func ensureSFTPStageRuntimeDirs(paths ...string) error {
	for _, path := range paths {
		clean := filepath.Clean(strings.TrimSpace(path))
		if clean == "." || clean == "" {
			return errors.New("stage path must not be empty")
		}
		if !filepath.IsAbs(clean) {
			return fmt.Errorf("stage path %q must be absolute", path)
		}
		if err := os.MkdirAll(clean, pluginRuntimeDirMode); err != nil {
			return fmt.Errorf("create stage dir %q: %w", clean, err)
		}
	}
	return nil
}

func localStagePathExists(path string) bool {
	_, err := os.Lstat(path)
	return err == nil
}

func removeLocalStageFile(root, path string) error {
	if err := os.Remove(path); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	}
	cleanupLocalStageParents(root, filepath.Dir(path))
	return nil
}

func cleanupLocalStageParents(root, start string) {
	root = filepath.Clean(root)
	current := filepath.Clean(start)
	for current != root && current != "." && current != string(os.PathSeparator) {
		if err := os.Remove(current); err != nil {
			var pathErr *os.PathError
			if errors.As(err, &pathErr) {
				if errors.Is(pathErr.Err, syscall.ENOTEMPTY) || errors.Is(pathErr.Err, syscall.EEXIST) {
					return
				}
			}
			return
		}
		current = filepath.Dir(current)
	}
}

func writeLocalStageFileFromReader(finalPath, tmpPath string, mode os.FileMode, reader io.Reader) error {
	if mode.Perm() == 0 {
		mode = sftpLocalStageDefaultFileMode
	}
	if err := os.MkdirAll(filepath.Dir(finalPath), pluginRuntimeDirMode); err != nil {
		return fmt.Errorf("create stage parent for %q: %w", finalPath, err)
	}
	if err := os.MkdirAll(filepath.Dir(tmpPath), pluginRuntimeDirMode); err != nil {
		return fmt.Errorf("create stage tmp parent for %q: %w", tmpPath, err)
	}

	file, err := os.OpenFile(tmpPath, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, mode.Perm())
	if err != nil {
		return fmt.Errorf("open stage tmp file %q: %w", tmpPath, err)
	}

	copyErr := func() error {
		if _, err := io.CopyBuffer(file, reader, make([]byte, defaultSFTPChunkBytes)); err != nil {
			return fmt.Errorf("write stage tmp file %q: %w", tmpPath, err)
		}
		if err := file.Chmod(mode.Perm()); err != nil {
			return fmt.Errorf("chmod stage tmp file %q: %w", tmpPath, err)
		}
		if err := file.Close(); err != nil {
			return fmt.Errorf("close stage tmp file %q: %w", tmpPath, err)
		}
		if err := os.Rename(tmpPath, finalPath); err != nil {
			return fmt.Errorf("rename stage tmp file %q to %q: %w", tmpPath, finalPath, err)
		}
		return nil
	}()
	if copyErr != nil {
		_ = file.Close()
		_ = os.Remove(tmpPath)
		return copyErr
	}
	return nil
}

func copyLocalFileToStage(srcPath, finalPath, tmpPath string, mode os.FileMode) error {
	src, err := os.Open(srcPath)
	if err != nil {
		return fmt.Errorf("open source stage file %q: %w", srcPath, err)
	}
	defer src.Close()

	return writeLocalStageFileFromReader(finalPath, tmpPath, mode, src)
}

func writeLocalStageMarker(finalPath, tmpPath string) error {
	return writeLocalStageFileFromReader(finalPath, tmpPath, sftpLocalStageDefaultFileMode, strings.NewReader(""))
}

func uploadLocalStageFile(client namespaceSFTPClient, localPath, remotePath string, mode os.FileMode) error {
	localFile, err := os.Open(localPath)
	if err != nil {
		return fmt.Errorf("open local stage file %q: %w", localPath, err)
	}
	defer localFile.Close()

	tmpRemotePath := remoteStageUploadTempPath(remotePath)
	parent := pathpkg.Dir(tmpRemotePath)
	if parent != "." {
		if err := client.MkdirAll(parent); err != nil {
			return fmt.Errorf("create remote temp parent %q: %w", parent, err)
		}
	}

	remoteFile, err := client.OpenFile(tmpRemotePath, os.O_CREATE|os.O_TRUNC|os.O_WRONLY)
	if err != nil {
		return fmt.Errorf("open remote temp file %q: %w", tmpRemotePath, err)
	}

	copyErr := func() error {
		if _, err := io.CopyBuffer(remoteFile, localFile, make([]byte, defaultSFTPChunkBytes)); err != nil {
			return fmt.Errorf("write remote temp file %q: %w", tmpRemotePath, err)
		}
		if err := remoteFile.Close(); err != nil {
			return fmt.Errorf("close remote temp file %q: %w", tmpRemotePath, err)
		}
		if err := renameRemoteStageFile(client, tmpRemotePath, remotePath); err != nil {
			return err
		}
		if mode.Perm() != 0 {
			if err := client.Chmod(remotePath, mode.Perm()); err != nil {
				return fmt.Errorf("chmod remote file %q: %w", remotePath, err)
			}
		}
		return nil
	}()
	if copyErr != nil {
		_ = remoteFile.Close()
		_ = client.Remove(tmpRemotePath)
		return copyErr
	}
	return nil
}

func remoteStageUploadTempPath(remotePath string) string {
	dir := pathpkg.Dir(remotePath)
	base := pathpkg.Base(remotePath)
	return joinSFTPPath(dir, fmt.Sprintf(".%s.netforge-tmp-%d", base, time.Now().UTC().UnixNano()))
}

func renameRemoteStageFile(client namespaceSFTPClient, fromPath, toPath string) error {
	if err := client.Rename(fromPath, toPath); err == nil {
		return nil
	}

	if _, statErr := client.Lstat(toPath); statErr == nil {
		if err := client.Remove(toPath); err != nil {
			return fmt.Errorf("remove existing remote file %q before rename: %w", toPath, err)
		}
		if err := client.Rename(fromPath, toPath); err != nil {
			return fmt.Errorf("rename remote temp file %q to %q: %w", fromPath, toPath, err)
		}
		return nil
	}

	if err := client.Rename(fromPath, toPath); err != nil {
		return fmt.Errorf("rename remote temp file %q to %q: %w", fromPath, toPath, err)
	}
	return nil
}

func downloadRemoteFileToLocalStage(client namespaceSFTPClient, remotePath, localFinalPath, localTmpPath string, mode os.FileMode) error {
	file, err := client.Open(remotePath)
	if err != nil {
		return fmt.Errorf("open remote source file %q: %w", remotePath, err)
	}
	defer file.Close()

	return writeLocalStageFileFromReader(localFinalPath, localTmpPath, mode, file)
}

func stageRemoteDirectoryToLocal(client namespaceSFTPClient, baseRemoteDir, remoteDir, localIncomingDir, localTmpDir string) (int, error) {
	entries, err := client.ReadDir(remoteDir)
	if err != nil {
		return 0, fmt.Errorf("read remote source directory %q: %w", remoteDir, err)
	}
	sort.Slice(entries, func(i, j int) bool {
		return entries[i].Name() < entries[j].Name()
	})

	copied := 0
	for _, entry := range entries {
		remotePath := joinSFTPPath(remoteDir, entry.Name())
		if entry.IsDir() {
			childCopied, err := stageRemoteDirectoryToLocal(client, baseRemoteDir, remotePath, localIncomingDir, localTmpDir)
			copied += childCopied
			if err != nil {
				return copied, err
			}
			continue
		}

		rel, err := sftpStageRelativeRemotePath(baseRemoteDir, remotePath)
		if err != nil {
			return copied, err
		}
		localFinalPath := sftpStageLocalPath(localIncomingDir, rel)
		if localStagePathExists(localFinalPath) {
			return copied, fmt.Errorf("source staging already contains %q", filepath.ToSlash(rel))
		}

		if err := downloadRemoteFileToLocalStage(
			client,
			remotePath,
			localFinalPath,
			sftpStageTempLocalPath(localTmpDir, rel),
			entry.Mode().Perm(),
		); err != nil {
			return copied, err
		}
		if err := deleteNamespaceSFTPPath(client, remotePath, false); err != nil {
			return copied, fmt.Errorf("delete remote source file %q: %w", remotePath, err)
		}
		copied++
	}

	return copied, nil
}

func uploadLocalDirectoryToRemote(client namespaceSFTPClient, incomingDir, tmpDir, ackDir, remoteDir string) (int, error) {
	files, err := listLocalStageFiles(incomingDir)
	if err != nil {
		return 0, err
	}

	uploaded := 0
	for _, file := range files {
		ackPath := sftpStageLocalPath(ackDir, file.RelPath)
		if localStagePathExists(ackPath) {
			if err := removeLocalStageFile(incomingDir, file.AbsPath); err != nil {
				return uploaded, fmt.Errorf("remove acknowledged destination staged file %q: %w", file.AbsPath, err)
			}
			continue
		}

		remotePath := joinSFTPPath(remoteDir, filepath.ToSlash(file.RelPath))
		if err := uploadLocalStageFile(client, file.AbsPath, remotePath, file.Mode); err != nil {
			return uploaded, err
		}
		if err := writeLocalStageMarker(ackPath, sftpStageAckTempLocalPath(tmpDir, file.RelPath)); err != nil {
			return uploaded, fmt.Errorf("write destination ack marker %q: %w", ackPath, err)
		}
		if err := removeLocalStageFile(incomingDir, file.AbsPath); err != nil {
			return uploaded, fmt.Errorf("remove uploaded destination staged file %q: %w", file.AbsPath, err)
		}
		uploaded++
	}

	return uploaded, nil
}

func runHostSFTPStageBridgeCycle(sourceIncomingDir, destinationIncomingDir, destinationTmpDir, destinationAckDir string) (sftpBridgeCycleResult, error) {
	completed, err := reapDestinationStageAcks(sourceIncomingDir, destinationAckDir)
	if err != nil {
		return sftpBridgeCycleResult{CompletedFiles: completed}, err
	}

	copied, err := copySourceStageToDestinationStage(sourceIncomingDir, destinationIncomingDir, destinationTmpDir, destinationAckDir)
	if err != nil {
		return sftpBridgeCycleResult{CompletedFiles: completed, CopiedFiles: copied}, err
	}

	return sftpBridgeCycleResult{
		CompletedFiles: completed,
		CopiedFiles:    copied,
	}, nil
}

func reapDestinationStageAcks(sourceIncomingDir, destinationAckDir string) (int, error) {
	ackPaths, err := listLocalAckPaths(destinationAckDir)
	if err != nil {
		return 0, err
	}

	completed := 0
	for _, rel := range ackPaths {
		sourcePath := sftpStageLocalPath(sourceIncomingDir, rel)
		if err := removeLocalStageFile(sourceIncomingDir, sourcePath); err != nil {
			return completed, fmt.Errorf("remove source staged file %q after acknowledgement: %w", sourcePath, err)
		}

		ackPath := sftpStageLocalPath(destinationAckDir, rel)
		if err := removeLocalStageFile(destinationAckDir, ackPath); err != nil {
			return completed, fmt.Errorf("remove destination acknowledgement %q: %w", ackPath, err)
		}
		completed++
	}

	return completed, nil
}

func copySourceStageToDestinationStage(sourceIncomingDir, destinationIncomingDir, destinationTmpDir, destinationAckDir string) (int, error) {
	files, err := listLocalStageFiles(sourceIncomingDir)
	if err != nil {
		return 0, err
	}

	copied := 0
	for _, file := range files {
		if localStagePathExists(sftpStageLocalPath(destinationAckDir, file.RelPath)) {
			continue
		}

		destinationPath := sftpStageLocalPath(destinationIncomingDir, file.RelPath)
		if localStagePathExists(destinationPath) {
			continue
		}

		if err := copyLocalFileToStage(
			file.AbsPath,
			destinationPath,
			sftpStageTempLocalPath(destinationTmpDir, file.RelPath),
			file.Mode,
		); err != nil {
			return copied, fmt.Errorf("copy staged file %q into destination queue: %w", file.AbsPath, err)
		}
		copied++
	}

	return copied, nil
}

func (s *namespaceHTTPService) StartSFTPStageDownload(req StartSFTPStageDownloadRequest) (*SFTPStageWorkerStatus, error) {
	req.RemoteDirectory = normalizeSFTPDirectory(req.RemoteDirectory)
	req.LocalIncomingDir = filepath.Clean(strings.TrimSpace(req.LocalIncomingDir))
	req.LocalTmpDir = filepath.Clean(strings.TrimSpace(req.LocalTmpDir))
	if req.JobID < 1 {
		return nil, fmt.Errorf("invalid job id %d", req.JobID)
	}
	if req.PollIntervalSeconds < 1 {
		return nil, fmt.Errorf("job %d download poll interval must be at least 1 second", req.JobID)
	}
	if err := ensureSFTPStageRuntimeDirs(req.LocalIncomingDir, req.LocalTmpDir); err != nil {
		return nil, err
	}

	s.mu.Lock()
	if s.downloadWorkers == nil {
		s.downloadWorkers = make(map[int64]sftpStageDownloadWorker)
	}
	if worker, exists := s.downloadWorkers[req.JobID]; exists && worker.status != nil {
		out := worker.status.snapshot()
		s.mu.Unlock()
		return &out, nil
	}

	ctx, cancel := context.WithCancel(context.Background())
	s.nextSFTPStageWorker++
	token := s.nextSFTPStageWorker
	status := newSFTPStageWorkerStatusState(req.JobID)
	status.setRunning(true)
	s.downloadWorkers[req.JobID] = sftpStageDownloadWorker{
		cancel: cancel,
		token:  token,
		status: status,
	}
	s.mu.Unlock()

	go s.runSFTPStageDownloadWorker(ctx, token, req, status)

	out := status.snapshot()
	return &out, nil
}

func (s *namespaceHTTPService) StopSFTPStageDownload(jobID int64) (*SFTPStageWorkerStatus, error) {
	s.mu.Lock()
	worker, exists := s.downloadWorkers[jobID]
	if exists {
		delete(s.downloadWorkers, jobID)
	}
	s.mu.Unlock()

	if !exists || worker.status == nil {
		return defaultSFTPStageWorkerStatus(jobID), nil
	}

	worker.status.setRunning(false)
	if worker.cancel != nil {
		worker.cancel()
	}
	out := worker.status.snapshot()
	return &out, nil
}

func (s *namespaceHTTPService) GetSFTPStageDownloadStatus(jobID int64) (*SFTPStageWorkerStatus, error) {
	s.mu.Lock()
	worker, exists := s.downloadWorkers[jobID]
	s.mu.Unlock()

	if !exists || worker.status == nil {
		return defaultSFTPStageWorkerStatus(jobID), nil
	}

	out := worker.status.snapshot()
	return &out, nil
}

func (s *namespaceHTTPService) StartSFTPStageUpload(req StartSFTPStageUploadRequest) (*SFTPStageWorkerStatus, error) {
	req.RemoteDirectory = normalizeSFTPDirectory(req.RemoteDirectory)
	req.LocalIncomingDir = filepath.Clean(strings.TrimSpace(req.LocalIncomingDir))
	req.LocalTmpDir = filepath.Clean(strings.TrimSpace(req.LocalTmpDir))
	req.LocalAckDir = filepath.Clean(strings.TrimSpace(req.LocalAckDir))
	if req.JobID < 1 {
		return nil, fmt.Errorf("invalid job id %d", req.JobID)
	}
	if req.PollIntervalSeconds < 1 {
		return nil, fmt.Errorf("job %d upload poll interval must be at least 1 second", req.JobID)
	}
	if err := ensureSFTPStageRuntimeDirs(req.LocalIncomingDir, req.LocalTmpDir, req.LocalAckDir); err != nil {
		return nil, err
	}

	s.mu.Lock()
	if s.uploadWorkers == nil {
		s.uploadWorkers = make(map[int64]sftpStageUploadWorker)
	}
	if worker, exists := s.uploadWorkers[req.JobID]; exists && worker.status != nil {
		out := worker.status.snapshot()
		s.mu.Unlock()
		return &out, nil
	}

	ctx, cancel := context.WithCancel(context.Background())
	s.nextSFTPStageWorker++
	token := s.nextSFTPStageWorker
	status := newSFTPStageWorkerStatusState(req.JobID)
	status.setRunning(true)
	s.uploadWorkers[req.JobID] = sftpStageUploadWorker{
		cancel: cancel,
		token:  token,
		status: status,
	}
	s.mu.Unlock()

	go s.runSFTPStageUploadWorker(ctx, token, req, status)

	out := status.snapshot()
	return &out, nil
}

func (s *namespaceHTTPService) StopSFTPStageUpload(jobID int64) (*SFTPStageWorkerStatus, error) {
	s.mu.Lock()
	worker, exists := s.uploadWorkers[jobID]
	if exists {
		delete(s.uploadWorkers, jobID)
	}
	s.mu.Unlock()

	if !exists || worker.status == nil {
		return defaultSFTPStageWorkerStatus(jobID), nil
	}

	worker.status.setRunning(false)
	if worker.cancel != nil {
		worker.cancel()
	}
	out := worker.status.snapshot()
	return &out, nil
}

func (s *namespaceHTTPService) GetSFTPStageUploadStatus(jobID int64) (*SFTPStageWorkerStatus, error) {
	s.mu.Lock()
	worker, exists := s.uploadWorkers[jobID]
	s.mu.Unlock()

	if !exists || worker.status == nil {
		return defaultSFTPStageWorkerStatus(jobID), nil
	}

	out := worker.status.snapshot()
	return &out, nil
}

func (s *namespaceHTTPService) runSFTPStageDownloadWorker(ctx context.Context, token uint64, req StartSFTPStageDownloadRequest, status *sftpStageWorkerStatusState) {
	defer func() {
		status.setRunning(false)
		s.mu.Lock()
		if current, exists := s.downloadWorkers[req.JobID]; exists && current.token == token {
			delete(s.downloadWorkers, req.JobID)
		}
		s.mu.Unlock()
	}()

	pollInterval := time.Duration(req.PollIntervalSeconds) * time.Second
	runCycle := func() {
		startedAt := time.Now().UTC()
		status.beginCycle(startedAt)

		client, err := openNamespaceSFTPClient(req.Connection)
		if err != nil {
			status.finishCycle(time.Now().UTC(), 0, err)
			log.Printf("namespace=%s sftp stage download job=%d: %v", s.cfg.Namespace, req.JobID, err)
			return
		}
		defer client.Close()

		files, err := stageRemoteDirectoryToLocal(client, req.RemoteDirectory, req.RemoteDirectory, req.LocalIncomingDir, req.LocalTmpDir)
		status.finishCycle(time.Now().UTC(), files, err)
		if err != nil {
			log.Printf("namespace=%s sftp stage download job=%d: %v", s.cfg.Namespace, req.JobID, err)
		}
	}

	runCycle()

	ticker := time.NewTicker(pollInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			runCycle()
		}
	}
}

func (s *namespaceHTTPService) runSFTPStageUploadWorker(ctx context.Context, token uint64, req StartSFTPStageUploadRequest, status *sftpStageWorkerStatusState) {
	defer func() {
		status.setRunning(false)
		s.mu.Lock()
		if current, exists := s.uploadWorkers[req.JobID]; exists && current.token == token {
			delete(s.uploadWorkers, req.JobID)
		}
		s.mu.Unlock()
	}()

	pollInterval := time.Duration(req.PollIntervalSeconds) * time.Second
	runCycle := func() {
		startedAt := time.Now().UTC()
		status.beginCycle(startedAt)

		client, err := openNamespaceSFTPClient(req.Connection)
		if err != nil {
			status.finishCycle(time.Now().UTC(), 0, err)
			log.Printf("namespace=%s sftp stage upload job=%d: %v", s.cfg.Namespace, req.JobID, err)
			return
		}
		defer client.Close()

		files, err := uploadLocalDirectoryToRemote(client, req.LocalIncomingDir, req.LocalTmpDir, req.LocalAckDir, req.RemoteDirectory)
		status.finishCycle(time.Now().UTC(), files, err)
		if err != nil {
			log.Printf("namespace=%s sftp stage upload job=%d: %v", s.cfg.Namespace, req.JobID, err)
		}
	}

	runCycle()

	ticker := time.NewTicker(pollInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			runCycle()
		}
	}
}
