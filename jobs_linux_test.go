//go:build linux

package main

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestSFTPSyncJobManagerCreateStartStopAndPipeline(t *testing.T) {
	persistentBase := t.TempDir()
	dbPath := filepath.Join(persistentBase, sftpJobsDBFilename)

	var (
		mu                sync.Mutex
		downloadStarts    []StartSFTPStageDownloadRequest
		uploadStarts      []StartSFTPStageUploadRequest
		downloadStops     []int64
		uploadStops       []int64
		sourceStageStatus SFTPStageWorkerStatus
		destStageStatus   SFTPStageWorkerStatus
	)

	sourceRPC := &stubNamespaceService{
		stageDownloadStartHook: func(req StartSFTPStageDownloadRequest) (*SFTPStageWorkerStatus, error) {
			mu.Lock()
			defer mu.Unlock()
			downloadStarts = append(downloadStarts, req)
			sourceStageStatus = SFTPStageWorkerStatus{
				JobID:      req.JobID,
				Running:    true,
				LastPollAt: formatStoredJobTime(time.Now().UTC()),
			}
			return &sourceStageStatus, nil
		},
		stageDownloadStopHook: func(jobID int64) (*SFTPStageWorkerStatus, error) {
			mu.Lock()
			defer mu.Unlock()
			downloadStops = append(downloadStops, jobID)
			sourceStageStatus.Running = false
			return &sourceStageStatus, nil
		},
		stageDownloadStatusHook: func(jobID int64) (*SFTPStageWorkerStatus, error) {
			mu.Lock()
			defer mu.Unlock()
			status := sourceStageStatus
			if status.JobID == 0 {
				status.JobID = jobID
			}
			return &status, nil
		},
	}
	destinationRPC := &stubNamespaceService{
		stageUploadStartHook: func(req StartSFTPStageUploadRequest) (*SFTPStageWorkerStatus, error) {
			mu.Lock()
			defer mu.Unlock()
			uploadStarts = append(uploadStarts, req)
			destStageStatus = SFTPStageWorkerStatus{
				JobID:      req.JobID,
				Running:    true,
				LastPollAt: formatStoredJobTime(time.Now().UTC()),
			}
			return &destStageStatus, nil
		},
		stageUploadStopHook: func(jobID int64) (*SFTPStageWorkerStatus, error) {
			mu.Lock()
			defer mu.Unlock()
			uploadStops = append(uploadStops, jobID)
			destStageStatus.Running = false
			return &destStageStatus, nil
		},
		stageUploadStatusHook: func(jobID int64) (*SFTPStageWorkerStatus, error) {
			mu.Lock()
			defer mu.Unlock()
			status := destStageStatus
			if status.JobID == 0 {
				status.JobID = jobID
			}
			return &status, nil
		},
	}

	plugins := []*runningPlugin{
		{cfg: NSConfig{Name: "srcns"}, rpc: sourceRPC},
		{cfg: NSConfig{Name: "dstns"}, rpc: destinationRPC},
	}
	manager, err := openSFTPSyncJobManager(dbPath, func(namespace string) *runningPlugin {
		for _, plugin := range plugins {
			if plugin.cfg.Name == namespace {
				return plugin
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("openSFTPSyncJobManager failed: %v", err)
	}
	defer manager.Close()

	job, err := manager.CreateJob(sftpSyncJobSpec{
		From: sftpEndpointConfig{
			Namespace: "srcns",
			Host:      "10.0.0.1",
			Port:      22,
			Username:  "source",
			Password:  "source-pass",
			Directory: "/from",
		},
		To: sftpEndpointConfig{
			Namespace: "dstns",
			Host:      "10.0.0.2",
			Port:      2022,
			Username:  "dest",
			Password:  "dest-pass",
			Directory: "/to",
		},
		Interval: 24 * time.Hour,
	})
	if err != nil {
		t.Fatalf("CreateJob failed: %v", err)
	}

	if _, err := manager.StartJob(job.ID); err != nil {
		t.Fatalf("StartJob failed: %v", err)
	}

	waitForJobSnapshot(t, manager, job.ID, func(view hostSFTPSyncJobView) bool {
		return view.Enabled && view.Running && view.SourceStageRunning && view.BridgeStageRunning && view.DestinationStageRunning
	})

	mu.Lock()
	gotDownloadStarts := append([]StartSFTPStageDownloadRequest(nil), downloadStarts...)
	gotUploadStarts := append([]StartSFTPStageUploadRequest(nil), uploadStarts...)
	mu.Unlock()

	if len(gotDownloadStarts) != 1 || gotDownloadStarts[0].LocalIncomingDir != "/data/sftp-jobs/1/incoming" || gotDownloadStarts[0].LocalTmpDir != "/data/sftp-jobs/1/tmp" {
		t.Fatalf("unexpected source stage download start request: %+v", gotDownloadStarts)
	}
	if len(gotUploadStarts) != 1 || gotUploadStarts[0].LocalIncomingDir != "/data/sftp-jobs/1/incoming" || gotUploadStarts[0].LocalTmpDir != "/data/sftp-jobs/1/tmp" || gotUploadStarts[0].LocalAckDir != "/data/sftp-jobs/1/acks" {
		t.Fatalf("unexpected destination stage upload start request: %+v", gotUploadStarts)
	}

	sourceHostFile := filepath.Join(manager.sourceIncomingDir(*job), "nested", "demo.txt")
	if err := os.MkdirAll(filepath.Dir(sourceHostFile), 0o755); err != nil {
		t.Fatalf("MkdirAll source host stage failed: %v", err)
	}
	if err := os.WriteFile(sourceHostFile, []byte("payload"), 0o640); err != nil {
		t.Fatalf("WriteFile source host stage failed: %v", err)
	}

	destinationHostFile := filepath.Join(manager.destinationIncomingDir(*job), "nested", "demo.txt")
	waitForPath(t, destinationHostFile)

	data, err := os.ReadFile(destinationHostFile)
	if err != nil {
		t.Fatalf("ReadFile destination host stage failed: %v", err)
	}
	if string(data) != "payload" {
		t.Fatalf("unexpected destination host stage content: %q", string(data))
	}
	if _, err := os.Stat(sourceHostFile); err != nil {
		t.Fatalf("expected source staged file to remain before ack, got %v", err)
	}

	mu.Lock()
	destStageStatus.LastSuccessAt = formatStoredJobTime(time.Now().UTC())
	mu.Unlock()
	if err := os.Remove(destinationHostFile); err != nil {
		t.Fatalf("Remove destination staged file failed: %v", err)
	}
	ackPath := filepath.Join(manager.destinationAckDir(*job), "nested", "demo.txt")
	if err := os.MkdirAll(filepath.Dir(ackPath), 0o755); err != nil {
		t.Fatalf("MkdirAll ack path failed: %v", err)
	}
	if err := os.WriteFile(ackPath, []byte{}, 0o600); err != nil {
		t.Fatalf("WriteFile ack path failed: %v", err)
	}

	waitForJobSnapshot(t, manager, job.ID, func(view hostSFTPSyncJobView) bool {
		return view.LastStatus == "success" && view.LastFilesCopied == 1
	})
	if _, err := os.Stat(sourceHostFile); !os.IsNotExist(err) {
		t.Fatalf("expected source staged file to be removed after ack, got %v", err)
	}
	if _, err := os.Stat(ackPath); !os.IsNotExist(err) {
		t.Fatalf("expected ack file to be reaped, got %v", err)
	}

	if _, err := manager.StopJob(job.ID); err != nil {
		t.Fatalf("StopJob failed: %v", err)
	}
	waitForJobSnapshot(t, manager, job.ID, func(view hostSFTPSyncJobView) bool {
		return !view.Enabled && !view.Running && !view.SourceStageRunning && !view.BridgeStageRunning && !view.DestinationStageRunning
	})

	mu.Lock()
	gotDownloadStops := append([]int64(nil), downloadStops...)
	gotUploadStops := append([]int64(nil), uploadStops...)
	mu.Unlock()
	if len(gotDownloadStops) == 0 || gotDownloadStops[0] != job.ID {
		t.Fatalf("expected source stage worker stop for job %d, got %+v", job.ID, gotDownloadStops)
	}
	if len(gotUploadStops) == 0 || gotUploadStops[0] != job.ID {
		t.Fatalf("expected destination stage worker stop for job %d, got %+v", job.ID, gotUploadStops)
	}

	manager2, err := openSFTPSyncJobManager(dbPath, func(namespace string) *runningPlugin {
		for _, plugin := range plugins {
			if plugin.cfg.Name == namespace {
				return plugin
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("reopen sftp job manager failed: %v", err)
	}
	defer manager2.Close()

	snapshot, err := manager2.Snapshot()
	if err != nil {
		t.Fatalf("Snapshot failed after reopen: %v", err)
	}
	if len(snapshot) != 1 || snapshot[0].ID != job.ID || snapshot[0].Enabled || snapshot[0].Running || snapshot[0].LastFilesCopied != 1 {
		t.Fatalf("unexpected snapshot after reopen: %+v", snapshot)
	}
}

func TestSFTPSyncJobManagerPersistsJobs(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), sftpJobsDBFilename)
	manager, err := openSFTPSyncJobManager(dbPath, func(string) *runningPlugin { return nil })
	if err != nil {
		t.Fatalf("openSFTPSyncJobManager failed: %v", err)
	}

	job, err := manager.CreateJob(sftpSyncJobSpec{
		From: sftpEndpointConfig{
			Namespace: "srcns",
			Host:      "10.0.0.1",
			Port:      22,
			Username:  "source",
			Password:  "source-pass",
			Directory: "/from",
		},
		To: sftpEndpointConfig{
			Namespace: "dstns",
			Host:      "10.0.0.2",
			Port:      2022,
			Username:  "dest",
			Password:  "dest-pass",
			Directory: "/to",
		},
		Interval: 5 * time.Minute,
	})
	if err != nil {
		t.Fatalf("CreateJob failed: %v", err)
	}
	if err := manager.Close(); err != nil {
		t.Fatalf("Close failed: %v", err)
	}

	manager, err = openSFTPSyncJobManager(dbPath, func(string) *runningPlugin { return nil })
	if err != nil {
		t.Fatalf("reopen sftp job manager failed: %v", err)
	}
	defer manager.Close()

	snapshot, err := manager.Snapshot()
	if err != nil {
		t.Fatalf("Snapshot failed: %v", err)
	}
	if len(snapshot) != 1 || snapshot[0].ID != job.ID || snapshot[0].FromAddress != "10.0.0.1:22" || snapshot[0].ToAddress != "10.0.0.2:2022" || snapshot[0].Interval != "5m0s" {
		t.Fatalf("unexpected persisted snapshot: %+v", snapshot)
	}
}

func TestSFTPSyncJobManagerDeleteStopsRunnerAndRemovesJob(t *testing.T) {
	persistentBase := t.TempDir()
	dbPath := filepath.Join(persistentBase, sftpJobsDBFilename)

	var (
		mu            sync.Mutex
		downloadStops []int64
		uploadStops   []int64
	)

	sourceRPC := &stubNamespaceService{
		stageDownloadStartHook: func(req StartSFTPStageDownloadRequest) (*SFTPStageWorkerStatus, error) {
			return &SFTPStageWorkerStatus{JobID: req.JobID, Running: true}, nil
		},
		stageDownloadStopHook: func(jobID int64) (*SFTPStageWorkerStatus, error) {
			mu.Lock()
			defer mu.Unlock()
			downloadStops = append(downloadStops, jobID)
			return &SFTPStageWorkerStatus{JobID: jobID}, nil
		},
		stageDownloadStatusHook: func(jobID int64) (*SFTPStageWorkerStatus, error) {
			return &SFTPStageWorkerStatus{JobID: jobID, Running: true}, nil
		},
	}
	destinationRPC := &stubNamespaceService{
		stageUploadStartHook: func(req StartSFTPStageUploadRequest) (*SFTPStageWorkerStatus, error) {
			return &SFTPStageWorkerStatus{JobID: req.JobID, Running: true}, nil
		},
		stageUploadStopHook: func(jobID int64) (*SFTPStageWorkerStatus, error) {
			mu.Lock()
			defer mu.Unlock()
			uploadStops = append(uploadStops, jobID)
			return &SFTPStageWorkerStatus{JobID: jobID}, nil
		},
		stageUploadStatusHook: func(jobID int64) (*SFTPStageWorkerStatus, error) {
			return &SFTPStageWorkerStatus{JobID: jobID, Running: true}, nil
		},
	}

	plugins := []*runningPlugin{
		{cfg: NSConfig{Name: "srcns"}, rpc: sourceRPC},
		{cfg: NSConfig{Name: "dstns"}, rpc: destinationRPC},
	}
	manager, err := openSFTPSyncJobManager(dbPath, func(namespace string) *runningPlugin {
		for _, plugin := range plugins {
			if plugin.cfg.Name == namespace {
				return plugin
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("openSFTPSyncJobManager failed: %v", err)
	}
	defer manager.Close()

	job, err := manager.CreateJob(sftpSyncJobSpec{
		From: sftpEndpointConfig{
			Namespace: "srcns",
			Host:      "10.0.0.1",
			Port:      22,
			Username:  "source",
			Password:  "source-pass",
			Directory: "/from",
		},
		To: sftpEndpointConfig{
			Namespace: "dstns",
			Host:      "10.0.0.2",
			Port:      22,
			Username:  "dest",
			Password:  "dest-pass",
			Directory: "/to",
		},
		Interval: 24 * time.Hour,
	})
	if err != nil {
		t.Fatalf("CreateJob failed: %v", err)
	}

	if _, err := manager.StartJob(job.ID); err != nil {
		t.Fatalf("StartJob failed: %v", err)
	}
	waitForJobSnapshot(t, manager, job.ID, func(view hostSFTPSyncJobView) bool {
		return view.Enabled && view.Running
	})

	sourceStageRoot := manager.sourceStageRoot(*job)
	destinationStageRoot := manager.destinationStageRoot(*job)
	if err := os.MkdirAll(sourceStageRoot, 0o755); err != nil {
		t.Fatalf("MkdirAll source stage root failed: %v", err)
	}
	if err := os.MkdirAll(destinationStageRoot, 0o755); err != nil {
		t.Fatalf("MkdirAll destination stage root failed: %v", err)
	}
	if err := os.WriteFile(filepath.Join(sourceStageRoot, "queued.txt"), []byte("queued"), 0o600); err != nil {
		t.Fatalf("WriteFile source stage failed: %v", err)
	}
	if err := os.WriteFile(filepath.Join(destinationStageRoot, "queued.txt"), []byte("queued"), 0o600); err != nil {
		t.Fatalf("WriteFile destination stage failed: %v", err)
	}

	deleted, err := manager.DeleteJob(job.ID)
	if err != nil {
		t.Fatalf("DeleteJob failed: %v", err)
	}
	if deleted.ID != job.ID {
		t.Fatalf("unexpected deleted job: %+v", deleted)
	}

	mu.Lock()
	gotDownloadStops := append([]int64(nil), downloadStops...)
	gotUploadStops := append([]int64(nil), uploadStops...)
	mu.Unlock()
	if len(gotDownloadStops) == 0 || gotDownloadStops[0] != job.ID {
		t.Fatalf("expected source worker stop on delete, got %+v", gotDownloadStops)
	}
	if len(gotUploadStops) == 0 || gotUploadStops[0] != job.ID {
		t.Fatalf("expected destination worker stop on delete, got %+v", gotUploadStops)
	}
	if _, err := os.Stat(sourceStageRoot); !os.IsNotExist(err) {
		t.Fatalf("expected source stage root to be removed, got %v", err)
	}
	if _, err := os.Stat(destinationStageRoot); !os.IsNotExist(err) {
		t.Fatalf("expected destination stage root to be removed, got %v", err)
	}

	snapshot, err := manager.Snapshot()
	if err != nil {
		t.Fatalf("Snapshot failed: %v", err)
	}
	if len(snapshot) != 0 {
		t.Fatalf("expected deleted job to be absent from snapshot, got %+v", snapshot)
	}
}

func TestHostDashboardServiceSFTPJobRoutes(t *testing.T) {
	persistentBase := t.TempDir()
	dbPath := filepath.Join(persistentBase, sftpJobsDBFilename)

	var (
		mu                sync.Mutex
		sourceStageStatus = SFTPStageWorkerStatus{}
		destStageStatus   = SFTPStageWorkerStatus{}
	)

	sourceRPC := &stubNamespaceService{
		stageDownloadStartHook: func(req StartSFTPStageDownloadRequest) (*SFTPStageWorkerStatus, error) {
			mu.Lock()
			defer mu.Unlock()
			sourceStageStatus = SFTPStageWorkerStatus{
				JobID:      req.JobID,
				Running:    true,
				LastPollAt: formatStoredJobTime(time.Now().UTC()),
			}
			return &sourceStageStatus, nil
		},
		stageDownloadStopHook: func(jobID int64) (*SFTPStageWorkerStatus, error) {
			mu.Lock()
			defer mu.Unlock()
			sourceStageStatus.Running = false
			return &sourceStageStatus, nil
		},
		stageDownloadStatusHook: func(jobID int64) (*SFTPStageWorkerStatus, error) {
			mu.Lock()
			defer mu.Unlock()
			status := sourceStageStatus
			if status.JobID == 0 {
				status.JobID = jobID
			}
			return &status, nil
		},
	}
	destinationRPC := &stubNamespaceService{
		stageUploadStartHook: func(req StartSFTPStageUploadRequest) (*SFTPStageWorkerStatus, error) {
			mu.Lock()
			defer mu.Unlock()
			destStageStatus = SFTPStageWorkerStatus{
				JobID:      req.JobID,
				Running:    true,
				LastPollAt: formatStoredJobTime(time.Now().UTC()),
			}
			return &destStageStatus, nil
		},
		stageUploadStopHook: func(jobID int64) (*SFTPStageWorkerStatus, error) {
			mu.Lock()
			defer mu.Unlock()
			destStageStatus.Running = false
			return &destStageStatus, nil
		},
		stageUploadStatusHook: func(jobID int64) (*SFTPStageWorkerStatus, error) {
			mu.Lock()
			defer mu.Unlock()
			status := destStageStatus
			if status.JobID == 0 {
				status.JobID = jobID
			}
			return &status, nil
		},
	}

	plugins := []*runningPlugin{
		{cfg: NSConfig{Name: "srcns"}, rpc: sourceRPC},
		{cfg: NSConfig{Name: "dstns"}, rpc: destinationRPC},
	}
	manager, err := openSFTPSyncJobManager(dbPath, func(namespace string) *runningPlugin {
		for _, plugin := range plugins {
			if plugin.cfg.Name == namespace {
				return plugin
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("openSFTPSyncJobManager failed: %v", err)
	}
	defer manager.Close()

	service := &hostDashboardService{
		addr:           "127.0.0.1:8090",
		parentNIC:      "eth0",
		runtimeBase:    "/var/lib/netforge",
		persistentBase: persistentBase,
		plugins:        plugins,
		jobManager:     manager,
	}

	createForm := url.Values{
		"from_namespace": {"srcns"},
		"from_host":      {"10.0.0.1"},
		"from_port":      {"22"},
		"from_username":  {"source"},
		"from_password":  {"source-pass"},
		"from_directory": {"/from"},
		"to_namespace":   {"dstns"},
		"to_host":        {"10.0.0.2"},
		"to_port":        {"2022"},
		"to_username":    {"dest"},
		"to_password":    {"dest-pass"},
		"to_directory":   {"/to"},
		"interval":       {"24h"},
	}
	createReq := httptest.NewRequest(http.MethodPost, "/sftp-jobs/create", strings.NewReader(createForm.Encode()))
	createReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	createRec := httptest.NewRecorder()
	service.routes().ServeHTTP(createRec, createReq)

	if createRec.Code != http.StatusOK {
		t.Fatalf("unexpected create status code: got %d want %d", createRec.Code, http.StatusOK)
	}
	if !strings.Contains(createRec.Body.String(), "Created SFTP sync job #1") {
		t.Fatalf("expected create success message, got %s", createRec.Body.String())
	}
	if strings.Contains(createRec.Body.String(), "source-pass") || strings.Contains(createRec.Body.String(), "dest-pass") {
		t.Fatalf("job create response leaked password: %s", createRec.Body.String())
	}

	startForm := url.Values{"job_id": {"1"}}
	startReq := httptest.NewRequest(http.MethodPost, "/sftp-jobs/start", strings.NewReader(startForm.Encode()))
	startReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	startRec := httptest.NewRecorder()
	service.routes().ServeHTTP(startRec, startReq)

	if startRec.Code != http.StatusOK {
		t.Fatalf("unexpected start status code: got %d want %d", startRec.Code, http.StatusOK)
	}
	body := startRec.Body.String()
	for _, want := range []string{"Started SFTP sync job #1", "source stage running", "host bridge running", "destination stage running"} {
		if !strings.Contains(body, want) {
			t.Fatalf("expected start body to contain %q, got %s", want, body)
		}
	}

	job, err := manager.loadJob(1)
	if err != nil {
		t.Fatalf("loadJob failed: %v", err)
	}
	sourceHostFile := filepath.Join(manager.sourceIncomingDir(job), "demo.txt")
	if err := os.MkdirAll(filepath.Dir(sourceHostFile), 0o755); err != nil {
		t.Fatalf("MkdirAll source host file failed: %v", err)
	}
	if err := os.WriteFile(sourceHostFile, []byte("payload"), 0o640); err != nil {
		t.Fatalf("WriteFile source host file failed: %v", err)
	}
	destinationHostFile := filepath.Join(manager.destinationIncomingDir(job), "demo.txt")
	waitForPath(t, destinationHostFile)
	if err := os.Remove(destinationHostFile); err != nil {
		t.Fatalf("Remove destination host file failed: %v", err)
	}
	mu.Lock()
	destStageStatus.LastSuccessAt = formatStoredJobTime(time.Now().UTC())
	mu.Unlock()
	ackPath := filepath.Join(manager.destinationAckDir(job), "demo.txt")
	if err := os.MkdirAll(filepath.Dir(ackPath), 0o755); err != nil {
		t.Fatalf("MkdirAll ack path failed: %v", err)
	}
	if err := os.WriteFile(ackPath, []byte{}, 0o600); err != nil {
		t.Fatalf("WriteFile ack path failed: %v", err)
	}

	waitForJobSnapshot(t, manager, 1, func(view hostSFTPSyncJobView) bool {
		return view.LastStatus == "success" && view.LastFilesCopied == 1
	})

	stopReq := httptest.NewRequest(http.MethodPost, "/sftp-jobs/stop", strings.NewReader(startForm.Encode()))
	stopReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	stopRec := httptest.NewRecorder()
	service.routes().ServeHTTP(stopRec, stopReq)
	if stopRec.Code != http.StatusOK {
		t.Fatalf("unexpected stop status code: got %d want %d", stopRec.Code, http.StatusOK)
	}
	if !strings.Contains(stopRec.Body.String(), "Stopped SFTP sync job #1") {
		t.Fatalf("expected stop success message, got %s", stopRec.Body.String())
	}

	deleteReq := httptest.NewRequest(http.MethodPost, "/sftp-jobs/delete", strings.NewReader(startForm.Encode()))
	deleteReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	deleteRec := httptest.NewRecorder()
	service.routes().ServeHTTP(deleteRec, deleteReq)
	if deleteRec.Code != http.StatusOK {
		t.Fatalf("unexpected delete status code: got %d want %d", deleteRec.Code, http.StatusOK)
	}
	if !strings.Contains(deleteRec.Body.String(), "Deleted SFTP sync job #1") || !strings.Contains(deleteRec.Body.String(), "no jobs configured") {
		t.Fatalf("unexpected delete response: %s", deleteRec.Body.String())
	}
}

func waitForPath(t *testing.T, path string) {
	t.Helper()

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(path); err == nil {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for path %q", path)
}

func waitForJobSnapshot(t *testing.T, manager *sftpSyncJobManager, jobID int64, predicate func(hostSFTPSyncJobView) bool) {
	t.Helper()

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		snapshot, err := manager.Snapshot()
		if err != nil {
			t.Fatalf("Snapshot failed: %v", err)
		}
		for _, job := range snapshot {
			if job.ID == jobID && predicate(job) {
				return
			}
		}
		time.Sleep(20 * time.Millisecond)
	}

	snapshot, err := manager.Snapshot()
	if err != nil {
		t.Fatalf("Snapshot failed: %v", err)
	}
	t.Fatalf("timed out waiting for job %d snapshot condition, latest snapshot: %+v", jobID, snapshot)
}
