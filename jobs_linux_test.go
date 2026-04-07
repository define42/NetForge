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

func TestSFTPSyncJobManagerEmbeddedEndpointKinds(t *testing.T) {
	type ensureCall struct {
		namespace string
		req       EnsureNamespaceSFTPUserRequest
	}
	type removeCall struct {
		namespace string
		req       RemoveNamespaceSFTPUserRequest
	}

	testCases := []struct {
		name              string
		from              sftpEndpointConfig
		to                sftpEndpointConfig
		wantCreateEnsures []ensureCall
		wantDownloadAddr  string
		wantDownloadDir   string
		wantUploadAddr    string
		wantUploadDir     string
		wantDeleteRemoves []removeCall
	}{
		{
			name: "client to embedded server",
			from: sftpEndpointConfig{
				Kind:      sftpEndpointKindClient,
				Namespace: "srcns",
				Host:      "10.0.0.1",
				Port:      22,
				Username:  "source",
				Password:  "source-pass",
				Directory: "/from",
			},
			to: sftpEndpointConfig{
				Kind:      sftpEndpointKindServer,
				Namespace: "dstns",
				Username:  "dest-user",
				Password:  "dest-pass",
			},
			wantCreateEnsures: []ensureCall{
				{
					namespace: "dstns",
					req: EnsureNamespaceSFTPUserRequest{
						Username: "dest-user",
						Password: "dest-pass",
						Root:     "/data/sftp-endpoints/1/destination",
						CanRead:  true,
						CanWrite: true,
					},
				},
			},
			wantDownloadAddr: "10.0.0.1:22",
			wantDownloadDir:  "/from",
			wantUploadAddr:   "127.0.0.1:2222",
			wantUploadDir:    "/",
			wantDeleteRemoves: []removeCall{
				{namespace: "dstns", req: RemoveNamespaceSFTPUserRequest{Username: "dest-user"}},
			},
		},
		{
			name: "embedded server to client",
			from: sftpEndpointConfig{
				Kind:      sftpEndpointKindServer,
				Namespace: "srcns",
				Username:  "source-user",
				Password:  "source-pass",
			},
			to: sftpEndpointConfig{
				Kind:      sftpEndpointKindClient,
				Namespace: "dstns",
				Host:      "10.0.0.2",
				Port:      2022,
				Username:  "dest",
				Password:  "dest-pass",
				Directory: "/archive",
			},
			wantCreateEnsures: []ensureCall{
				{
					namespace: "srcns",
					req: EnsureNamespaceSFTPUserRequest{
						Username: "source-user",
						Password: "source-pass",
						Root:     "/data/sftp-endpoints/1/source",
						CanRead:  true,
						CanWrite: true,
					},
				},
			},
			wantDownloadAddr: "127.0.0.1:2222",
			wantDownloadDir:  "/",
			wantUploadAddr:   "10.0.0.2:2022",
			wantUploadDir:    "/archive",
			wantDeleteRemoves: []removeCall{
				{namespace: "srcns", req: RemoveNamespaceSFTPUserRequest{Username: "source-user"}},
			},
		},
		{
			name: "embedded server to embedded server",
			from: sftpEndpointConfig{
				Kind:      sftpEndpointKindServer,
				Namespace: "srcns",
				Username:  "source-user",
				Password:  "source-pass",
			},
			to: sftpEndpointConfig{
				Kind:      sftpEndpointKindServer,
				Namespace: "dstns",
				Username:  "dest-user",
				Password:  "dest-pass",
			},
			wantCreateEnsures: []ensureCall{
				{
					namespace: "srcns",
					req: EnsureNamespaceSFTPUserRequest{
						Username: "source-user",
						Password: "source-pass",
						Root:     "/data/sftp-endpoints/1/source",
						CanRead:  true,
						CanWrite: true,
					},
				},
				{
					namespace: "dstns",
					req: EnsureNamespaceSFTPUserRequest{
						Username: "dest-user",
						Password: "dest-pass",
						Root:     "/data/sftp-endpoints/1/destination",
						CanRead:  true,
						CanWrite: true,
					},
				},
			},
			wantDownloadAddr: "127.0.0.1:2222",
			wantDownloadDir:  "/",
			wantUploadAddr:   "127.0.0.1:2222",
			wantUploadDir:    "/",
			wantDeleteRemoves: []removeCall{
				{namespace: "srcns", req: RemoveNamespaceSFTPUserRequest{Username: "source-user"}},
				{namespace: "dstns", req: RemoveNamespaceSFTPUserRequest{Username: "dest-user"}},
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			persistentBase := t.TempDir()
			dbPath := filepath.Join(persistentBase, sftpJobsDBFilename)

			var (
				mu             sync.Mutex
				ensureCalls    []ensureCall
				removeCalls    []removeCall
				downloadStarts []StartSFTPStageDownloadRequest
				uploadStarts   []StartSFTPStageUploadRequest
			)

			sourceRPC := &stubNamespaceService{
				ensureSFTPUserHook: func(req EnsureNamespaceSFTPUserRequest) (*NamespaceSFTPUserStatusResponse, error) {
					mu.Lock()
					defer mu.Unlock()
					ensureCalls = append(ensureCalls, ensureCall{namespace: "srcns", req: req})
					return &NamespaceSFTPUserStatusResponse{Username: req.Username, Exists: true, Root: req.Root, CanRead: req.CanRead, CanWrite: req.CanWrite}, nil
				},
				removeSFTPUserHook: func(req RemoveNamespaceSFTPUserRequest) (*NamespaceSFTPUserStatusResponse, error) {
					mu.Lock()
					defer mu.Unlock()
					removeCalls = append(removeCalls, removeCall{namespace: "srcns", req: req})
					return &NamespaceSFTPUserStatusResponse{Username: req.Username}, nil
				},
				stageDownloadStartHook: func(req StartSFTPStageDownloadRequest) (*SFTPStageWorkerStatus, error) {
					mu.Lock()
					defer mu.Unlock()
					downloadStarts = append(downloadStarts, req)
					return &SFTPStageWorkerStatus{JobID: req.JobID, Running: true}, nil
				},
				stageDownloadStatusHook: func(jobID int64) (*SFTPStageWorkerStatus, error) {
					return &SFTPStageWorkerStatus{JobID: jobID, Running: true}, nil
				},
			}
			destinationRPC := &stubNamespaceService{
				ensureSFTPUserHook: func(req EnsureNamespaceSFTPUserRequest) (*NamespaceSFTPUserStatusResponse, error) {
					mu.Lock()
					defer mu.Unlock()
					ensureCalls = append(ensureCalls, ensureCall{namespace: "dstns", req: req})
					return &NamespaceSFTPUserStatusResponse{Username: req.Username, Exists: true, Root: req.Root, CanRead: req.CanRead, CanWrite: req.CanWrite}, nil
				},
				removeSFTPUserHook: func(req RemoveNamespaceSFTPUserRequest) (*NamespaceSFTPUserStatusResponse, error) {
					mu.Lock()
					defer mu.Unlock()
					removeCalls = append(removeCalls, removeCall{namespace: "dstns", req: req})
					return &NamespaceSFTPUserStatusResponse{Username: req.Username}, nil
				},
				stageUploadStartHook: func(req StartSFTPStageUploadRequest) (*SFTPStageWorkerStatus, error) {
					mu.Lock()
					defer mu.Unlock()
					uploadStarts = append(uploadStarts, req)
					return &SFTPStageWorkerStatus{JobID: req.JobID, Running: true}, nil
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
				From:     tc.from,
				To:       tc.to,
				Interval: 5 * time.Minute,
			})
			if err != nil {
				t.Fatalf("CreateJob failed: %v", err)
			}

			mu.Lock()
			gotCreateEnsures := append([]ensureCall(nil), ensureCalls...)
			ensureCalls = nil
			mu.Unlock()
			if len(gotCreateEnsures) != len(tc.wantCreateEnsures) {
				t.Fatalf("unexpected create ensure count: got %+v want %+v", gotCreateEnsures, tc.wantCreateEnsures)
			}
			for i := range tc.wantCreateEnsures {
				if gotCreateEnsures[i].namespace != tc.wantCreateEnsures[i].namespace || gotCreateEnsures[i].req != tc.wantCreateEnsures[i].req {
					t.Fatalf("unexpected create ensure call %d: got %+v want %+v", i, gotCreateEnsures[i], tc.wantCreateEnsures[i])
				}
			}

			if _, err := manager.StartJob(job.ID); err != nil {
				t.Fatalf("StartJob failed: %v", err)
			}

			mu.Lock()
			gotDownloadStarts := append([]StartSFTPStageDownloadRequest(nil), downloadStarts...)
			gotUploadStarts := append([]StartSFTPStageUploadRequest(nil), uploadStarts...)
			gotStopRemoves := append([]removeCall(nil), removeCalls...)
			mu.Unlock()

			if len(gotDownloadStarts) != 1 || gotDownloadStarts[0].Connection.Address != tc.wantDownloadAddr || gotDownloadStarts[0].RemoteDirectory != tc.wantDownloadDir {
				t.Fatalf("unexpected download stage request: %+v", gotDownloadStarts)
			}
			if len(gotUploadStarts) != 1 || gotUploadStarts[0].Connection.Address != tc.wantUploadAddr || gotUploadStarts[0].RemoteDirectory != tc.wantUploadDir {
				t.Fatalf("unexpected upload stage request: %+v", gotUploadStarts)
			}
			if len(gotStopRemoves) != 0 {
				t.Fatalf("expected no embedded-user removals before stop, got %+v", gotStopRemoves)
			}

			if _, err := manager.StopJob(job.ID); err != nil {
				t.Fatalf("StopJob failed: %v", err)
			}

			mu.Lock()
			gotStopRemoves = append([]removeCall(nil), removeCalls...)
			mu.Unlock()
			if len(gotStopRemoves) != 0 {
				t.Fatalf("expected stop to leave embedded users intact, got %+v", gotStopRemoves)
			}

			if tc.from.usesEmbeddedSFTPServer() {
				if err := os.MkdirAll(manager.sourceEndpointRoot(*job), 0o755); err != nil {
					t.Fatalf("MkdirAll source endpoint root failed: %v", err)
				}
			}
			if tc.to.usesEmbeddedSFTPServer() {
				if err := os.MkdirAll(manager.destinationEndpointRoot(*job), 0o755); err != nil {
					t.Fatalf("MkdirAll destination endpoint root failed: %v", err)
				}
			}

			if _, err := manager.DeleteJob(job.ID); err != nil {
				t.Fatalf("DeleteJob failed: %v", err)
			}

			mu.Lock()
			gotDeleteRemoves := append([]removeCall(nil), removeCalls...)
			mu.Unlock()
			if len(gotDeleteRemoves) != len(tc.wantDeleteRemoves) {
				t.Fatalf("unexpected delete remove count: got %+v want %+v", gotDeleteRemoves, tc.wantDeleteRemoves)
			}
			for i := range tc.wantDeleteRemoves {
				if gotDeleteRemoves[i] != tc.wantDeleteRemoves[i] {
					t.Fatalf("unexpected delete remove call %d: got %+v want %+v", i, gotDeleteRemoves[i], tc.wantDeleteRemoves[i])
				}
			}
			if tc.from.usesEmbeddedSFTPServer() {
				if _, err := os.Stat(manager.sourceEndpointRoot(*job)); !os.IsNotExist(err) {
					t.Fatalf("expected source endpoint root removal, got %v", err)
				}
			}
			if tc.to.usesEmbeddedSFTPServer() {
				if _, err := os.Stat(manager.destinationEndpointRoot(*job)); !os.IsNotExist(err) {
					t.Fatalf("expected destination endpoint root removal, got %v", err)
				}
			}
		})
	}
}

func TestSFTPSyncJobManagerRejectsDuplicateEmbeddedSFTPUsers(t *testing.T) {
	persistentBase := t.TempDir()
	dbPath := filepath.Join(persistentBase, sftpJobsDBFilename)

	plugins := []*runningPlugin{
		{cfg: NSConfig{Name: "srcns"}, rpc: &stubNamespaceService{}},
		{cfg: NSConfig{Name: "dstns"}, rpc: &stubNamespaceService{}},
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

	if _, err := manager.CreateJob(sftpSyncJobSpec{
		From: sftpEndpointConfig{
			Kind:      sftpEndpointKindClient,
			Namespace: "srcns",
			Host:      "10.0.0.1",
			Port:      22,
			Username:  "source",
			Password:  "source-pass",
			Directory: "/from",
		},
		To: sftpEndpointConfig{
			Kind:      sftpEndpointKindServer,
			Namespace: "dstns",
			Username:  "shared-user",
			Password:  "dest-pass",
		},
		Interval: 5 * time.Minute,
	}); err != nil {
		t.Fatalf("initial CreateJob failed: %v", err)
	}

	_, err = manager.CreateJob(sftpSyncJobSpec{
		From: sftpEndpointConfig{
			Kind:      sftpEndpointKindClient,
			Namespace: "srcns",
			Host:      "10.0.0.3",
			Port:      22,
			Username:  "source-2",
			Password:  "source-pass-2",
			Directory: "/from-2",
		},
		To: sftpEndpointConfig{
			Kind:      sftpEndpointKindServer,
			Namespace: "dstns",
			Username:  "shared-user",
			Password:  "dest-pass-2",
		},
		Interval: 10 * time.Minute,
	})
	if err == nil || !strings.Contains(err.Error(), "already used") {
		t.Fatalf("expected duplicate embedded-user validation error, got %v", err)
	}
}

func TestHostDashboardServiceSFTPServerJobRoute(t *testing.T) {
	persistentBase := t.TempDir()
	dbPath := filepath.Join(persistentBase, sftpJobsDBFilename)

	sourceRPC := &stubNamespaceService{}
	destinationRPC := &stubNamespaceService{}
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
		"from_kind":      {"sftpserver"},
		"from_namespace": {"srcns"},
		"from_username":  {"source-user"},
		"from_password":  {"source-pass"},
		"to_kind":        {"sftpserver"},
		"to_namespace":   {"dstns"},
		"to_username":    {"dest-user"},
		"to_password":    {"dest-pass"},
		"interval":       {"30m"},
	}
	req := httptest.NewRequest(http.MethodPost, "/sftp-jobs/create", strings.NewReader(createForm.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	service.routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("unexpected create status code: got %d want %d", rec.Code, http.StatusOK)
	}
	body := rec.Body.String()
	for _, want := range []string{"Created SFTP sync job #1", "sftpserver", "127.0.0.1:2222", "<code>/</code>"} {
		if !strings.Contains(body, want) {
			t.Fatalf("expected create body to contain %q, got %s", want, body)
		}
	}
	if strings.Contains(body, "source-pass") || strings.Contains(body, "dest-pass") {
		t.Fatalf("sftpserver job create response leaked password: %s", body)
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
