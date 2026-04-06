//go:build linux

package main

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"path/filepath"
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
	ID                            int64  `json:"id"`
	FromNamespace                 string `json:"from_namespace"`
	FromAddress                   string `json:"from_address"`
	FromUsername                  string `json:"from_username"`
	FromDirectory                 string `json:"from_directory"`
	ToNamespace                   string `json:"to_namespace"`
	ToAddress                     string `json:"to_address"`
	ToUsername                    string `json:"to_username"`
	ToDirectory                   string `json:"to_directory"`
	Interval                      string `json:"interval"`
	Enabled                       bool   `json:"enabled"`
	Running                       bool   `json:"running"`
	LastStatus                    string `json:"last_status"`
	LastError                     string `json:"last_error,omitempty"`
	LastFilesCopied               int    `json:"last_files_copied"`
	LastRunAt                     string `json:"last_run_at,omitempty"`
	LastSuccessAt                 string `json:"last_success_at,omitempty"`
	SourceStageRunning            bool   `json:"source_stage_running"`
	SourceStageLastRunAt          string `json:"source_stage_last_run_at,omitempty"`
	SourceStageLastSuccessAt      string `json:"source_stage_last_success_at,omitempty"`
	SourceStageLastError          string `json:"source_stage_last_error,omitempty"`
	DestinationStageRunning       bool   `json:"destination_stage_running"`
	DestinationStageLastRunAt     string `json:"destination_stage_last_run_at,omitempty"`
	DestinationStageLastSuccessAt string `json:"destination_stage_last_success_at,omitempty"`
	DestinationStageLastError     string `json:"destination_stage_last_error,omitempty"`
	BridgeStageRunning            bool   `json:"bridge_stage_running"`
	BridgeStageLastRunAt          string `json:"bridge_stage_last_run_at,omitempty"`
	BridgeStageLastSuccessAt      string `json:"bridge_stage_last_success_at,omitempty"`
	BridgeStageLastError          string `json:"bridge_stage_last_error,omitempty"`
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
	persistentBase     string
	pluginForNamespace func(string) *runningPlugin
	runners            map[int64]sftpSyncJobRunner
	nextRunnerToken    uint64
	now                func() time.Time
	closed             bool
}

type sftpSyncJobRunner struct {
	cancel       context.CancelFunc
	token        uint64
	job          sftpSyncJob
	bridgeStatus *sftpStageWorkerStatusState
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
		persistentBase:     filepath.Dir(filepath.Clean(dbPath)),
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
			if err := manager.startRunner(job); err != nil {
				_ = db.Close()
				return nil, err
			}
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
	runners := make([]sftpSyncJobRunner, 0, len(m.runners))
	for _, runner := range m.runners {
		runners = append(runners, runner)
	}
	m.runners = make(map[int64]sftpSyncJobRunner)
	m.mu.Unlock()

	for _, runner := range runners {
		if runner.cancel != nil {
			runner.cancel()
		}
		m.stopNamespaceStageWorkers(runner.job)
	}
	return m.db.Close()
}

func (m *sftpSyncJobManager) Snapshot() ([]hostSFTPSyncJobView, error) {
	jobs, err := m.listJobs()
	if err != nil {
		return nil, err
	}

	m.mu.Lock()
	running := make(map[int64]sftpSyncJobRunner, len(m.runners))
	for id, runner := range m.runners {
		running[id] = runner
	}
	m.mu.Unlock()

	views := make([]hostSFTPSyncJobView, 0, len(jobs))
	for _, job := range jobs {
		view := hostSFTPSyncJobView{
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
			LastStatus:      job.LastStatus,
			LastError:       job.LastError,
			LastFilesCopied: job.LastFilesCopied,
			LastRunAt:       formatDashboardJobTime(job.LastRunAt),
			LastSuccessAt:   formatDashboardJobTime(job.LastSuccessAt),
		}

		if runner, exists := running[job.ID]; exists {
			view.Running = true
			view.BridgeStageRunning = true
			if runner.bridgeStatus != nil {
				bridgeStatus := runner.bridgeStatus.snapshot()
				view.BridgeStageRunning = bridgeStatus.Running
				view.BridgeStageLastRunAt = formatDashboardJobTime(parseStoredJobTime(bridgeStatus.LastPollAt))
				view.BridgeStageLastSuccessAt = formatDashboardJobTime(parseStoredJobTime(bridgeStatus.LastSuccessAt))
				view.BridgeStageLastError = bridgeStatus.LastError
				if view.LastSuccessAt == "" && bridgeStatus.LastSuccessAt != "" {
					view.LastSuccessAt = formatDashboardJobTime(parseStoredJobTime(bridgeStatus.LastSuccessAt))
				}
			}
		}

		sourceStatus, sourceErr := m.lookupStageDownloadStatus(job)
		if sourceErr != nil {
			view.SourceStageLastError = sourceErr.Error()
		} else if sourceStatus != nil {
			view.SourceStageRunning = sourceStatus.Running
			view.SourceStageLastRunAt = formatDashboardJobTime(parseStoredJobTime(sourceStatus.LastPollAt))
			view.SourceStageLastSuccessAt = formatDashboardJobTime(parseStoredJobTime(sourceStatus.LastSuccessAt))
			view.SourceStageLastError = sourceStatus.LastError
			if sourceStatus.LastPollAt != "" {
				view.LastRunAt = formatDashboardJobTime(parseStoredJobTime(sourceStatus.LastPollAt))
			}
		}

		destinationStatus, destinationErr := m.lookupStageUploadStatus(job)
		if destinationErr != nil {
			view.DestinationStageLastError = destinationErr.Error()
		} else if destinationStatus != nil {
			view.DestinationStageRunning = destinationStatus.Running
			view.DestinationStageLastRunAt = formatDashboardJobTime(parseStoredJobTime(destinationStatus.LastPollAt))
			view.DestinationStageLastSuccessAt = formatDashboardJobTime(parseStoredJobTime(destinationStatus.LastSuccessAt))
			view.DestinationStageLastError = destinationStatus.LastError
		}

		if view.LastError == "" {
			switch {
			case view.SourceStageLastError != "":
				view.LastError = "source stage: " + view.SourceStageLastError
			case view.DestinationStageLastError != "":
				view.LastError = "destination stage: " + view.DestinationStageLastError
			case view.BridgeStageLastError != "":
				view.LastError = "host bridge: " + view.BridgeStageLastError
			}
		}
		if view.LastError != "" && view.Enabled {
			view.LastStatus = "error"
		} else if view.Running && view.LastStatus == "stopped" {
			view.LastStatus = "running"
		}

		views = append(views, view)
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
	job, err := m.loadJob(id)
	if err != nil {
		return nil, err
	}
	if err := m.startRunner(job); err != nil {
		return nil, err
	}
	if err := m.setJobEnabled(id, true); err != nil {
		m.cancelRunner(id)
		return nil, err
	}
	if err := m.markJobRunning(id); err != nil {
		m.cancelRunner(id)
		_ = m.setJobEnabled(id, false)
		return nil, err
	}
	job, err = m.loadJob(id)
	if err != nil {
		return nil, err
	}
	return &job, nil
}

func (m *sftpSyncJobManager) StopJob(id int64) (*sftpSyncJob, error) {
	if id < 1 {
		return nil, fmt.Errorf("invalid job id %d", id)
	}
	m.cancelRunner(id)
	if err := m.setJobEnabled(id, false); err != nil {
		return nil, err
	}
	if err := m.markJobStopped(id); err != nil {
		return nil, err
	}

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
	if err := m.removeJobStageDirs(job); err != nil {
		return nil, err
	}

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

func (m *sftpSyncJobManager) cancelRunner(id int64) {
	m.mu.Lock()
	runner, exists := m.runners[id]
	delete(m.runners, id)
	m.mu.Unlock()

	if exists && runner.cancel != nil {
		runner.cancel()
	}
	if exists {
		m.stopNamespaceStageWorkers(runner.job)
	}
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

func (m *sftpSyncJobManager) startRunner(job sftpSyncJob) error {
	m.mu.Lock()
	if m.closed {
		m.mu.Unlock()
		return errors.New("sftp job manager is closed")
	}
	if _, exists := m.runners[job.ID]; exists {
		m.mu.Unlock()
		return nil
	}
	m.mu.Unlock()

	sourceRPC, err := m.lookupNamespaceRPC(job.From.Namespace)
	if err != nil {
		return fmt.Errorf("source namespace %q: %w", job.From.Namespace, err)
	}
	destinationRPC, err := m.lookupNamespaceRPC(job.To.Namespace)
	if err != nil {
		return fmt.Errorf("destination namespace %q: %w", job.To.Namespace, err)
	}

	if _, err := sourceRPC.StartSFTPStageDownload(m.downloadStageRequest(job)); err != nil {
		return fmt.Errorf("start source stage worker for job %d: %w", job.ID, err)
	}
	if _, err := destinationRPC.StartSFTPStageUpload(m.uploadStageRequest(job)); err != nil {
		_, _ = sourceRPC.StopSFTPStageDownload(job.ID)
		return fmt.Errorf("start destination stage worker for job %d: %w", job.ID, err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	bridgeStatus := newSFTPStageWorkerStatusState(job.ID)
	bridgeStatus.setRunning(true)

	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed {
		cancel()
		bridgeStatus.setRunning(false)
		m.stopNamespaceStageWorkers(job)
		return errors.New("sftp job manager is closed")
	}
	if _, exists := m.runners[job.ID]; exists {
		cancel()
		bridgeStatus.setRunning(false)
		return nil
	}
	m.nextRunnerToken++
	runnerToken := m.nextRunnerToken
	m.runners[job.ID] = sftpSyncJobRunner{
		cancel:       cancel,
		token:        runnerToken,
		job:          job,
		bridgeStatus: bridgeStatus,
	}

	go m.runBridgeWorker(ctx, runnerToken, job, sourceRPC, destinationRPC, bridgeStatus)
	return nil
}

func (m *sftpSyncJobManager) runBridgeWorker(ctx context.Context, runnerToken uint64, job sftpSyncJob, sourceRPC, destinationRPC NamespaceService, bridgeStatus *sftpStageWorkerStatusState) {
	defer func() {
		bridgeStatus.setRunning(false)
		m.mu.Lock()
		if current, exists := m.runners[job.ID]; exists && current.token == runnerToken {
			delete(m.runners, job.ID)
		}
		m.mu.Unlock()
	}()

	runCycle := func() {
		startedAt := m.now().UTC()
		bridgeStatus.beginCycle(startedAt)

		sourceStatus, sourceErr := sourceRPC.GetSFTPStageDownloadStatus(job.ID)
		if sourceErr == nil && sourceStatus != nil {
			if sourceStatus.LastPollAt != "" {
				if parsed := parseStoredJobTime(sourceStatus.LastPollAt); !parsed.IsZero() {
					_ = m.recordJobLastRun(job.ID, parsed)
				}
			}
			if sourceStatus.LastError != "" {
				_ = m.markJobError(job.ID, "source stage: "+sourceStatus.LastError)
			}
		}

		destinationStatus, destinationErr := destinationRPC.GetSFTPStageUploadStatus(job.ID)
		if destinationErr == nil && destinationStatus != nil && destinationStatus.LastError != "" {
			_ = m.markJobError(job.ID, "destination stage: "+destinationStatus.LastError)
		}

		result, bridgeErr := runHostSFTPStageBridgeCycle(
			m.sourceIncomingDir(job),
			m.destinationIncomingDir(job),
			m.destinationTmpDir(job),
			m.destinationAckDir(job),
		)
		bridgeStatus.finishCycle(m.now().UTC(), result.CompletedFiles, bridgeErr)

		switch {
		case bridgeErr != nil:
			_ = m.markJobError(job.ID, "host bridge: "+bridgeErr.Error())
		case sourceErr != nil:
			_ = m.markJobError(job.ID, "source stage status: "+sourceErr.Error())
		case destinationErr != nil:
			_ = m.markJobError(job.ID, "destination stage status: "+destinationErr.Error())
		case result.CompletedFiles > 0:
			_ = m.markJobCompleted(job.ID, result.CompletedFiles)
		default:
			_ = m.markJobRunning(job.ID)
		}
	}

	runCycle()

	ticker := time.NewTicker(sftpLocalStagePollInterval)
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

func (m *sftpSyncJobManager) markJobRunning(id int64) error {
	now := m.now().UTC()
	_, err := m.db.Exec(`UPDATE sftp_sync_jobs SET last_status = 'running', last_error = '', updated_at = ? WHERE id = ?`,
		formatStoredJobTime(now),
		id,
	)
	if err != nil {
		return fmt.Errorf("mark sftp sync job %d running: %w", id, err)
	}
	return nil
}

func (m *sftpSyncJobManager) markJobStopped(id int64) error {
	now := m.now().UTC()
	_, err := m.db.Exec(`UPDATE sftp_sync_jobs SET last_status = 'stopped', last_error = '', updated_at = ? WHERE id = ?`,
		formatStoredJobTime(now),
		id,
	)
	if err != nil {
		return fmt.Errorf("mark sftp sync job %d stopped: %w", id, err)
	}
	return nil
}

func (m *sftpSyncJobManager) recordJobLastRun(id int64, lastRunAt time.Time) error {
	if lastRunAt.IsZero() {
		return nil
	}
	_, err := m.db.Exec(`UPDATE sftp_sync_jobs SET last_run_at = ?, updated_at = ? WHERE id = ?`,
		formatStoredJobTime(lastRunAt.UTC()),
		formatStoredJobTime(m.now().UTC()),
		id,
	)
	if err != nil {
		return fmt.Errorf("record sftp sync job %d last run: %w", id, err)
	}
	return nil
}

func (m *sftpSyncJobManager) markJobError(id int64, message string) error {
	now := m.now().UTC()
	_, err := m.db.Exec(`UPDATE sftp_sync_jobs SET last_status = 'error', last_error = ?, updated_at = ? WHERE id = ?`,
		message,
		formatStoredJobTime(now),
		id,
	)
	if err != nil {
		return fmt.Errorf("mark sftp sync job %d error: %w", id, err)
	}
	return nil
}

func (m *sftpSyncJobManager) markJobCompleted(id int64, completedFiles int) error {
	now := m.now().UTC()
	_, err := m.db.Exec(`UPDATE sftp_sync_jobs SET last_status = 'success', last_error = '', last_files_copied = last_files_copied + ?, last_success_at = ?, updated_at = ? WHERE id = ?`,
		completedFiles,
		formatStoredJobTime(now),
		formatStoredJobTime(now),
		id,
	)
	if err != nil {
		return fmt.Errorf("mark sftp sync job %d completed: %w", id, err)
	}
	return nil
}

func (m *sftpSyncJobManager) downloadStageRequest(job sftpSyncJob) StartSFTPStageDownloadRequest {
	return StartSFTPStageDownloadRequest{
		JobID:               job.ID,
		Connection:          job.From.connectionInfo(),
		RemoteDirectory:     job.From.Directory,
		LocalIncomingDir:    sftpJobIncomingDir(pluginSandboxDataDir, job.ID),
		LocalTmpDir:         sftpJobTmpDir(pluginSandboxDataDir, job.ID),
		PollIntervalSeconds: int64(job.Interval / time.Second),
	}
}

func (m *sftpSyncJobManager) uploadStageRequest(job sftpSyncJob) StartSFTPStageUploadRequest {
	return StartSFTPStageUploadRequest{
		JobID:               job.ID,
		Connection:          job.To.connectionInfo(),
		RemoteDirectory:     job.To.Directory,
		LocalIncomingDir:    sftpJobIncomingDir(pluginSandboxDataDir, job.ID),
		LocalTmpDir:         sftpJobTmpDir(pluginSandboxDataDir, job.ID),
		LocalAckDir:         sftpJobAckDir(pluginSandboxDataDir, job.ID),
		PollIntervalSeconds: int64(sftpLocalStagePollInterval / time.Second),
	}
}

func (m *sftpSyncJobManager) sourceStageRoot(job sftpSyncJob) string {
	return sftpJobStageRoot(persistentPluginDataDir(m.persistentBase, job.From.Namespace), job.ID)
}

func (m *sftpSyncJobManager) destinationStageRoot(job sftpSyncJob) string {
	return sftpJobStageRoot(persistentPluginDataDir(m.persistentBase, job.To.Namespace), job.ID)
}

func (m *sftpSyncJobManager) sourceIncomingDir(job sftpSyncJob) string {
	return sftpJobIncomingDir(persistentPluginDataDir(m.persistentBase, job.From.Namespace), job.ID)
}

func (m *sftpSyncJobManager) destinationIncomingDir(job sftpSyncJob) string {
	return sftpJobIncomingDir(persistentPluginDataDir(m.persistentBase, job.To.Namespace), job.ID)
}

func (m *sftpSyncJobManager) destinationTmpDir(job sftpSyncJob) string {
	return sftpJobTmpDir(persistentPluginDataDir(m.persistentBase, job.To.Namespace), job.ID)
}

func (m *sftpSyncJobManager) destinationAckDir(job sftpSyncJob) string {
	return sftpJobAckDir(persistentPluginDataDir(m.persistentBase, job.To.Namespace), job.ID)
}

func (m *sftpSyncJobManager) removeJobStageDirs(job sftpSyncJob) error {
	for _, root := range []string{
		m.sourceStageRoot(job),
		m.destinationStageRoot(job),
	} {
		if err := os.RemoveAll(root); err != nil {
			return fmt.Errorf("remove job stage root %q: %w", root, err)
		}
	}
	return nil
}

func (m *sftpSyncJobManager) stopNamespaceStageWorkers(job sftpSyncJob) {
	sourceRPC, err := m.lookupNamespaceRPC(job.From.Namespace)
	if err == nil {
		if _, err := sourceRPC.StopSFTPStageDownload(job.ID); err != nil {
			log.Printf("stop source stage worker for job %d: %v", job.ID, err)
		}
	}

	destinationRPC, err := m.lookupNamespaceRPC(job.To.Namespace)
	if err == nil {
		if _, err := destinationRPC.StopSFTPStageUpload(job.ID); err != nil {
			log.Printf("stop destination stage worker for job %d: %v", job.ID, err)
		}
	}
}

func (m *sftpSyncJobManager) lookupStageDownloadStatus(job sftpSyncJob) (*SFTPStageWorkerStatus, error) {
	sourceRPC, err := m.lookupNamespaceRPC(job.From.Namespace)
	if err != nil {
		return nil, err
	}
	return sourceRPC.GetSFTPStageDownloadStatus(job.ID)
}

func (m *sftpSyncJobManager) lookupStageUploadStatus(job sftpSyncJob) (*SFTPStageWorkerStatus, error) {
	destinationRPC, err := m.lookupNamespaceRPC(job.To.Namespace)
	if err != nil {
		return nil, err
	}
	return destinationRPC.GetSFTPStageUploadStatus(job.ID)
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
	if spec.From.Namespace == spec.To.Namespace {
		return sftpSyncJobSpec{}, errors.New("source and destination namespaces must differ")
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

// Legacy direct-transfer helper retained for focused streaming tests.
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
