//go:build linux

package main

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	_ "modernc.org/sqlite"
)

const sftpJobsDBFilename = "sftp-jobs.sqlite"

var sftpSyncChunkSize = defaultSFTPChunkBytes

type sftpEndpointConfig struct {
	Namespace string
	Host      string
	Port      int
	Username  string
	Password  string
	Directory string
}

func (c sftpEndpointConfig) connectionInfo() SFTPConnectionInfo {
	return SFTPConnectionInfo{
		Address:               net.JoinHostPort(c.Host, strconv.Itoa(c.Port)),
		Username:              c.Username,
		Password:              c.Password,
		InsecureIgnoreHostKey: true,
	}
}

type sftpSyncJobSpec struct {
	From     sftpEndpointConfig
	To       sftpEndpointConfig
	Interval time.Duration
}

type sftpSyncJob struct {
	ID              int64
	From            sftpEndpointConfig
	To              sftpEndpointConfig
	Interval        time.Duration
	Enabled         bool
	LastRunAt       time.Time
	LastSuccessAt   time.Time
	LastStatus      string
	LastError       string
	LastFilesCopied int
	CreatedAt       time.Time
	UpdatedAt       time.Time
}

type hostSFTPSyncJobView struct {
	ID              int64  `json:"id"`
	FromNamespace   string `json:"from_namespace"`
	FromAddress     string `json:"from_address"`
	FromUsername    string `json:"from_username"`
	FromDirectory   string `json:"from_directory"`
	ToNamespace     string `json:"to_namespace"`
	ToAddress       string `json:"to_address"`
	ToUsername      string `json:"to_username"`
	ToDirectory     string `json:"to_directory"`
	Interval        string `json:"interval"`
	Enabled         bool   `json:"enabled"`
	Running         bool   `json:"running"`
	LastStatus      string `json:"last_status"`
	LastError       string `json:"last_error,omitempty"`
	LastFilesCopied int    `json:"last_files_copied"`
	LastRunAt       string `json:"last_run_at,omitempty"`
	LastSuccessAt   string `json:"last_success_at,omitempty"`
}

type hostSFTPSyncJobFormData struct {
	FromNamespace string `json:"from_namespace,omitempty"`
	FromHost      string `json:"from_host,omitempty"`
	FromPort      string `json:"from_port,omitempty"`
	FromUsername  string `json:"from_username,omitempty"`
	FromDirectory string `json:"from_directory,omitempty"`
	ToNamespace   string `json:"to_namespace,omitempty"`
	ToHost        string `json:"to_host,omitempty"`
	ToPort        string `json:"to_port,omitempty"`
	ToUsername    string `json:"to_username,omitempty"`
	ToDirectory   string `json:"to_directory,omitempty"`
	Interval      string `json:"interval,omitempty"`
}

type sftpSyncJobManager struct {
	mu                 sync.Mutex
	db                 *sql.DB
	pluginForNamespace func(string) *runningPlugin
	runners            map[int64]sftpSyncJobRunner
	nextRunnerToken    uint64
	now                func() time.Time
	closed             bool
}

type sftpSyncJobRunner struct {
	cancel context.CancelFunc
	token  uint64
}

func openSFTPSyncJobManager(dbPath string, pluginForNamespace func(string) *runningPlugin) (*sftpSyncJobManager, error) {
	if pluginForNamespace == nil {
		return nil, errors.New("plugin resolver is required")
	}

	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		return nil, fmt.Errorf("open sftp jobs database %q: %w", dbPath, err)
	}
	db.SetMaxOpenConns(1)

	if _, err := db.Exec(`PRAGMA busy_timeout = 5000`); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("configure sftp jobs database timeout: %w", err)
	}
	if _, err := db.Exec(`
CREATE TABLE IF NOT EXISTS sftp_sync_jobs (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	from_namespace TEXT NOT NULL,
	from_host TEXT NOT NULL,
	from_port INTEGER NOT NULL,
	from_username TEXT NOT NULL,
	from_password TEXT NOT NULL,
	from_directory TEXT NOT NULL,
	to_namespace TEXT NOT NULL,
	to_host TEXT NOT NULL,
	to_port INTEGER NOT NULL,
	to_username TEXT NOT NULL,
	to_password TEXT NOT NULL,
	to_directory TEXT NOT NULL,
	interval_seconds INTEGER NOT NULL,
	enabled INTEGER NOT NULL DEFAULT 0,
	last_run_at TEXT NOT NULL DEFAULT '',
	last_success_at TEXT NOT NULL DEFAULT '',
	last_status TEXT NOT NULL DEFAULT 'stopped',
	last_error TEXT NOT NULL DEFAULT '',
	last_files_copied INTEGER NOT NULL DEFAULT 0,
	created_at TEXT NOT NULL,
	updated_at TEXT NOT NULL
)`); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("ensure sftp jobs schema: %w", err)
	}

	manager := &sftpSyncJobManager{
		db:                 db,
		pluginForNamespace: pluginForNamespace,
		runners:            make(map[int64]sftpSyncJobRunner),
		now:                time.Now,
	}

	jobs, err := manager.listJobs()
	if err != nil {
		_ = db.Close()
		return nil, err
	}
	for _, job := range jobs {
		if job.Enabled {
			manager.startRunner(job)
		}
	}

	return manager, nil
}

func (m *sftpSyncJobManager) Close() error {
	m.mu.Lock()
	if m.closed {
		m.mu.Unlock()
		return nil
	}
	m.closed = true
	cancels := make([]context.CancelFunc, 0, len(m.runners))
	for _, runner := range m.runners {
		cancels = append(cancels, runner.cancel)
	}
	m.runners = make(map[int64]sftpSyncJobRunner)
	m.mu.Unlock()

	for _, cancel := range cancels {
		cancel()
	}
	return m.db.Close()
}

func (m *sftpSyncJobManager) Snapshot() ([]hostSFTPSyncJobView, error) {
	jobs, err := m.listJobs()
	if err != nil {
		return nil, err
	}

	m.mu.Lock()
	running := make(map[int64]bool, len(m.runners))
	for id := range m.runners {
		running[id] = true
	}
	m.mu.Unlock()

	views := make([]hostSFTPSyncJobView, 0, len(jobs))
	for _, job := range jobs {
		views = append(views, hostSFTPSyncJobView{
			ID:              job.ID,
			FromNamespace:   job.From.Namespace,
			FromAddress:     net.JoinHostPort(job.From.Host, strconv.Itoa(job.From.Port)),
			FromUsername:    job.From.Username,
			FromDirectory:   job.From.Directory,
			ToNamespace:     job.To.Namespace,
			ToAddress:       net.JoinHostPort(job.To.Host, strconv.Itoa(job.To.Port)),
			ToUsername:      job.To.Username,
			ToDirectory:     job.To.Directory,
			Interval:        job.Interval.String(),
			Enabled:         job.Enabled,
			Running:         running[job.ID],
			LastStatus:      job.LastStatus,
			LastError:       job.LastError,
			LastFilesCopied: job.LastFilesCopied,
			LastRunAt:       formatDashboardJobTime(job.LastRunAt),
			LastSuccessAt:   formatDashboardJobTime(job.LastSuccessAt),
		})
	}
	return views, nil
}

func (m *sftpSyncJobManager) CreateJob(spec sftpSyncJobSpec) (*sftpSyncJob, error) {
	spec, err := normalizeAndValidateSFTPSyncJobSpec(spec)
	if err != nil {
		return nil, err
	}

	now := m.now().UTC()
	result, err := m.db.Exec(`
INSERT INTO sftp_sync_jobs (
	from_namespace, from_host, from_port, from_username, from_password, from_directory,
	to_namespace, to_host, to_port, to_username, to_password, to_directory,
	interval_seconds, enabled, last_run_at, last_success_at, last_status, last_error, last_files_copied,
	created_at, updated_at
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0, '', '', 'stopped', '', 0, ?, ?)`,
		spec.From.Namespace,
		spec.From.Host,
		spec.From.Port,
		spec.From.Username,
		spec.From.Password,
		spec.From.Directory,
		spec.To.Namespace,
		spec.To.Host,
		spec.To.Port,
		spec.To.Username,
		spec.To.Password,
		spec.To.Directory,
		int64(spec.Interval/time.Second),
		formatStoredJobTime(now),
		formatStoredJobTime(now),
	)
	if err != nil {
		return nil, fmt.Errorf("insert sftp sync job: %w", err)
	}

	id, err := result.LastInsertId()
	if err != nil {
		return nil, fmt.Errorf("read inserted sftp sync job id: %w", err)
	}
	job, err := m.loadJob(id)
	if err != nil {
		return nil, err
	}
	return &job, nil
}

func (m *sftpSyncJobManager) StartJob(id int64) (*sftpSyncJob, error) {
	if id < 1 {
		return nil, fmt.Errorf("invalid job id %d", id)
	}
	if err := m.setJobEnabled(id, true); err != nil {
		return nil, err
	}

	job, err := m.loadJob(id)
	if err != nil {
		return nil, err
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed {
		return nil, errors.New("sftp job manager is closed")
	}
	if _, exists := m.runners[id]; !exists {
		m.startRunnerLocked(job)
	}
	return &job, nil
}

func (m *sftpSyncJobManager) StopJob(id int64) (*sftpSyncJob, error) {
	if id < 1 {
		return nil, fmt.Errorf("invalid job id %d", id)
	}
	if err := m.setJobEnabled(id, false); err != nil {
		return nil, err
	}

	m.cancelRunner(id)

	job, err := m.loadJob(id)
	if err != nil {
		return nil, err
	}
	return &job, nil
}

func (m *sftpSyncJobManager) DeleteJob(id int64) (*sftpSyncJob, error) {
	if id < 1 {
		return nil, fmt.Errorf("invalid job id %d", id)
	}

	job, err := m.loadJob(id)
	if err != nil {
		return nil, err
	}

	m.cancelRunner(id)

	result, err := m.db.Exec(`DELETE FROM sftp_sync_jobs WHERE id = ?`, id)
	if err != nil {
		return nil, fmt.Errorf("delete sftp sync job %d: %w", id, err)
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return nil, fmt.Errorf("read sftp sync job %d delete count: %w", id, err)
	}
	if rows == 0 {
		return nil, fmt.Errorf("sftp sync job %d not found", id)
	}

	return &job, nil
}

func (m *sftpSyncJobManager) runJobNow(id int64) error {
	job, err := m.loadJob(id)
	if err != nil {
		return err
	}

	startedAt := m.now().UTC()
	if _, err := m.db.Exec(`UPDATE sftp_sync_jobs SET last_run_at = ?, last_status = 'running', last_error = '', updated_at = ? WHERE id = ?`,
		formatStoredJobTime(startedAt),
		formatStoredJobTime(startedAt),
		id,
	); err != nil {
		return fmt.Errorf("mark sftp sync job %d running: %w", id, err)
	}

	copied, runErr := m.syncJob(job)
	completedAt := m.now().UTC()
	if runErr != nil {
		if _, err := m.db.Exec(`UPDATE sftp_sync_jobs SET last_status = 'error', last_error = ?, last_files_copied = ?, updated_at = ? WHERE id = ?`,
			runErr.Error(),
			copied,
			formatStoredJobTime(completedAt),
			id,
		); err != nil {
			return fmt.Errorf("update failed sftp sync job %d status: %w", id, err)
		}
		return runErr
	}

	if _, err := m.db.Exec(`UPDATE sftp_sync_jobs SET last_status = 'success', last_error = '', last_files_copied = ?, last_success_at = ?, updated_at = ? WHERE id = ?`,
		copied,
		formatStoredJobTime(completedAt),
		formatStoredJobTime(completedAt),
		id,
	); err != nil {
		return fmt.Errorf("update successful sftp sync job %d status: %w", id, err)
	}
	return nil
}

func (m *sftpSyncJobManager) syncJob(job sftpSyncJob) (int, error) {
	sourceRPC, err := m.lookupNamespaceRPC(job.From.Namespace)
	if err != nil {
		return 0, fmt.Errorf("source namespace %q: %w", job.From.Namespace, err)
	}
	destinationRPC, err := m.lookupNamespaceRPC(job.To.Namespace)
	if err != nil {
		return 0, fmt.Errorf("destination namespace %q: %w", job.To.Namespace, err)
	}

	return syncSFTPDirectoryTree(sourceRPC, destinationRPC, job.From, job.To, job.From.Directory, job.To.Directory)
}

func (m *sftpSyncJobManager) cancelRunner(id int64) {
	m.mu.Lock()
	runner := m.runners[id]
	delete(m.runners, id)
	m.mu.Unlock()

	if runner.cancel != nil {
		runner.cancel()
	}
}

func syncSFTPDirectoryTree(sourceRPC, destinationRPC NamespaceService, source, destination sftpEndpointConfig, sourceDir, destinationDir string) (int, error) {
	listResp, err := sourceRPC.SFTPList(SFTPListRequest{
		Connection: source.connectionInfo(),
		Directory:  sourceDir,
	})
	if err != nil {
		return 0, fmt.Errorf("list source directory %q: %w", sourceDir, err)
	}

	copied := 0
	for _, entry := range listResp.Entries {
		if entry.IsDir {
			childDestinationDir := joinSFTPPath(destinationDir, entry.Name)
			childCopied, err := syncSFTPDirectoryTree(sourceRPC, destinationRPC, source, destination, entry.Path, childDestinationDir)
			copied += childCopied
			if err != nil {
				return copied, err
			}
			continue
		}

		targetPath := joinSFTPPath(destinationDir, entry.Name)
		if err := streamSFTPFile(sourceRPC, destinationRPC, source, destination, entry.Path, targetPath, entry.Size, entry.Mode); err != nil {
			return copied, fmt.Errorf("push destination file %q: %w", targetPath, err)
		}
		copied++
	}

	return copied, nil
}

func streamSFTPFile(sourceRPC, destinationRPC NamespaceService, source, destination sftpEndpointConfig, sourcePath, destinationPath string, size int64, mode uint32) error {
	if size == 0 {
		_, err := destinationRPC.SFTPPushChunk(SFTPPushChunkRequest{
			Connection:    destination.connectionInfo(),
			Path:          destinationPath,
			Offset:        0,
			Data:          []byte{},
			Mode:          mode & 0o777,
			CreateParents: true,
			Truncate:      true,
		})
		if err != nil {
			return fmt.Errorf("create empty destination file %q: %w", destinationPath, err)
		}
		return deleteSourceSFTPFile(sourceRPC, source, sourcePath)
	}

	chunkSize := sftpSyncChunkSize
	if chunkSize < 1 || chunkSize > maxSFTPTransferBytes {
		chunkSize = defaultSFTPChunkBytes
	}

	var offset int64
	for {
		chunkResp, err := sourceRPC.SFTPFetchChunk(SFTPFetchChunkRequest{
			Connection: source.connectionInfo(),
			Path:       sourcePath,
			Offset:     offset,
			Length:     chunkSize,
		})
		if err != nil {
			return fmt.Errorf("fetch source chunk %q at offset %d: %w", sourcePath, offset, err)
		}
		if chunkResp.Offset != offset {
			return fmt.Errorf("unexpected chunk offset for %q: got %d want %d", sourcePath, chunkResp.Offset, offset)
		}

		if len(chunkResp.Data) == 0 {
			if chunkResp.EOF {
				return nil
			}
			return fmt.Errorf("empty chunk for %q at offset %d before eof", sourcePath, offset)
		}

		chunkMode := chunkResp.Mode & 0o777
		if chunkMode == 0 {
			chunkMode = mode & 0o777
		}
		if _, err := destinationRPC.SFTPPushChunk(SFTPPushChunkRequest{
			Connection:    destination.connectionInfo(),
			Path:          destinationPath,
			Offset:        offset,
			Data:          chunkResp.Data,
			Mode:          chunkMode,
			CreateParents: offset == 0,
			Truncate:      offset == 0,
		}); err != nil {
			return fmt.Errorf("push destination chunk %q at offset %d: %w", destinationPath, offset, err)
		}

		offset += int64(len(chunkResp.Data))
		if chunkResp.EOF {
			return deleteSourceSFTPFile(sourceRPC, source, sourcePath)
		}
	}
}

func deleteSourceSFTPFile(sourceRPC NamespaceService, source sftpEndpointConfig, sourcePath string) error {
	if _, err := sourceRPC.SFTPDelete(SFTPDeleteRequest{
		Connection: source.connectionInfo(),
		Path:       sourcePath,
	}); err != nil {
		return fmt.Errorf("delete source file %q: %w", sourcePath, err)
	}
	return nil
}

func (m *sftpSyncJobManager) lookupNamespaceRPC(namespace string) (NamespaceService, error) {
	plugin := m.pluginForNamespace(namespace)
	if plugin == nil {
		return nil, fmt.Errorf("unknown namespace")
	}
	if plugin.rpc == nil {
		return nil, errors.New("plugin rpc unavailable")
	}
	return plugin.rpc, nil
}

func (m *sftpSyncJobManager) startRunner(job sftpSyncJob) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed {
		return
	}
	m.startRunnerLocked(job)
}

func (m *sftpSyncJobManager) startRunnerLocked(job sftpSyncJob) {
	if _, exists := m.runners[job.ID]; exists {
		return
	}

	ctx, cancel := context.WithCancel(context.Background())
	m.nextRunnerToken++
	runnerToken := m.nextRunnerToken
	m.runners[job.ID] = sftpSyncJobRunner{cancel: cancel, token: runnerToken}

	go func(interval time.Duration, jobID int64, runnerCancel context.CancelFunc, runnerToken uint64) {
		defer func() {
			m.mu.Lock()
			if current, exists := m.runners[jobID]; exists && current.token == runnerToken {
				delete(m.runners, jobID)
			}
			m.mu.Unlock()
		}()

		_ = m.runJobNow(jobID)

		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				_ = m.runJobNow(jobID)
			}
		}
	}(job.Interval, job.ID, cancel, runnerToken)
}

func (m *sftpSyncJobManager) setJobEnabled(id int64, enabled bool) error {
	now := m.now().UTC()
	result, err := m.db.Exec(`UPDATE sftp_sync_jobs SET enabled = ?, updated_at = ? WHERE id = ?`, boolToInt64(enabled), formatStoredJobTime(now), id)
	if err != nil {
		return fmt.Errorf("update sftp sync job %d enabled=%t: %w", id, enabled, err)
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("read sftp sync job %d update count: %w", id, err)
	}
	if rows == 0 {
		return fmt.Errorf("sftp sync job %d not found", id)
	}
	return nil
}

func (m *sftpSyncJobManager) listJobs() ([]sftpSyncJob, error) {
	rows, err := m.db.Query(`
SELECT
	id,
	from_namespace,
	from_host,
	from_port,
	from_username,
	from_password,
	from_directory,
	to_namespace,
	to_host,
	to_port,
	to_username,
	to_password,
	to_directory,
	interval_seconds,
	enabled,
	last_run_at,
	last_success_at,
	last_status,
	last_error,
	last_files_copied,
	created_at,
	updated_at
FROM sftp_sync_jobs
ORDER BY id ASC`)
	if err != nil {
		return nil, fmt.Errorf("query sftp sync jobs: %w", err)
	}
	defer rows.Close()

	var jobs []sftpSyncJob
	for rows.Next() {
		job, err := scanSFTPSyncJob(rows)
		if err != nil {
			return nil, err
		}
		jobs = append(jobs, job)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate sftp sync jobs: %w", err)
	}
	return jobs, nil
}

func (m *sftpSyncJobManager) loadJob(id int64) (sftpSyncJob, error) {
	row := m.db.QueryRow(`
SELECT
	id,
	from_namespace,
	from_host,
	from_port,
	from_username,
	from_password,
	from_directory,
	to_namespace,
	to_host,
	to_port,
	to_username,
	to_password,
	to_directory,
	interval_seconds,
	enabled,
	last_run_at,
	last_success_at,
	last_status,
	last_error,
	last_files_copied,
	created_at,
	updated_at
FROM sftp_sync_jobs
WHERE id = ?`, id)

	job, err := scanSFTPSyncJob(row)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return sftpSyncJob{}, fmt.Errorf("sftp sync job %d not found", id)
		}
		return sftpSyncJob{}, err
	}
	return job, nil
}

func scanSFTPSyncJob(scanner interface{ Scan(dest ...any) error }) (sftpSyncJob, error) {
	var (
		job             sftpSyncJob
		fromPort        int
		toPort          int
		intervalSeconds int64
		enabled         int64
		lastRunRaw      string
		lastSuccessRaw  string
		createdRaw      string
		updatedRaw      string
	)

	if err := scanner.Scan(
		&job.ID,
		&job.From.Namespace,
		&job.From.Host,
		&fromPort,
		&job.From.Username,
		&job.From.Password,
		&job.From.Directory,
		&job.To.Namespace,
		&job.To.Host,
		&toPort,
		&job.To.Username,
		&job.To.Password,
		&job.To.Directory,
		&intervalSeconds,
		&enabled,
		&lastRunRaw,
		&lastSuccessRaw,
		&job.LastStatus,
		&job.LastError,
		&job.LastFilesCopied,
		&createdRaw,
		&updatedRaw,
	); err != nil {
		return sftpSyncJob{}, fmt.Errorf("scan sftp sync job: %w", err)
	}

	job.From.Port = fromPort
	job.To.Port = toPort
	job.Interval = time.Duration(intervalSeconds) * time.Second
	job.Enabled = enabled != 0
	job.LastRunAt = parseStoredJobTime(lastRunRaw)
	job.LastSuccessAt = parseStoredJobTime(lastSuccessRaw)
	job.CreatedAt = parseStoredJobTime(createdRaw)
	job.UpdatedAt = parseStoredJobTime(updatedRaw)
	return job, nil
}

func normalizeAndValidateSFTPSyncJobSpec(spec sftpSyncJobSpec) (sftpSyncJobSpec, error) {
	spec.From = normalizeSFTPEndpointConfig(spec.From)
	spec.To = normalizeSFTPEndpointConfig(spec.To)
	if err := validateSFTPEndpointConfig(spec.From, "source"); err != nil {
		return sftpSyncJobSpec{}, err
	}
	if err := validateSFTPEndpointConfig(spec.To, "destination"); err != nil {
		return sftpSyncJobSpec{}, err
	}
	if spec.Interval < time.Second {
		return sftpSyncJobSpec{}, fmt.Errorf("job interval must be at least %s", time.Second)
	}
	return spec, nil
}

func normalizeSFTPEndpointConfig(cfg sftpEndpointConfig) sftpEndpointConfig {
	cfg.Namespace = strings.TrimSpace(cfg.Namespace)
	cfg.Host = strings.Trim(strings.TrimSpace(cfg.Host), "[]")
	cfg.Username = strings.TrimSpace(cfg.Username)
	cfg.Directory = normalizeSFTPDirectory(cfg.Directory)
	return cfg
}

func validateSFTPEndpointConfig(cfg sftpEndpointConfig, label string) error {
	if !validNamespaceName.MatchString(cfg.Namespace) {
		return fmt.Errorf("invalid %s namespace %q", label, cfg.Namespace)
	}
	if cfg.Host == "" {
		return fmt.Errorf("%s host is required", label)
	}
	if cfg.Port < 1 || cfg.Port > 65535 {
		return fmt.Errorf("%s port %d is out of range", label, cfg.Port)
	}
	if cfg.Username == "" {
		return fmt.Errorf("%s username is required", label)
	}
	if cfg.Password == "" {
		return fmt.Errorf("%s password is required", label)
	}
	if cfg.Directory == "" {
		return fmt.Errorf("%s directory is required", label)
	}
	return nil
}

func formatDashboardJobTime(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format(time.RFC3339)
}

func formatStoredJobTime(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format(time.RFC3339Nano)
}

func parseStoredJobTime(raw string) time.Time {
	if raw == "" {
		return time.Time{}
	}
	parsed, err := time.Parse(time.RFC3339Nano, raw)
	if err != nil {
		return time.Time{}
	}
	return parsed
}

func boolToInt64(v bool) int64 {
	if v {
		return 1
	}
	return 0
}

func parseDashboardJobInterval(raw string) (time.Duration, error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return 0, errors.New("job interval is required")
	}
	interval, err := time.ParseDuration(trimmed)
	if err != nil {
		return 0, fmt.Errorf("invalid job interval %q", raw)
	}
	return interval, nil
}
