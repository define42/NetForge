//go:build linux

package main

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestSFTPSyncJobManagerCreateStartStopAndSync(t *testing.T) {
	var (
		originalChunkSize = sftpSyncChunkSize
		mu                sync.Mutex
		pushes            []SFTPPushChunkRequest
		fetches           []SFTPFetchChunkRequest
		deletes           []SFTPDeleteRequest
		sourceRPC         = &stubNamespaceService{
			sftpListHook: func(req SFTPListRequest) (*SFTPListResponse, error) {
				switch req.Directory {
				case "/from":
					return &SFTPListResponse{
						Entries: []SFTPEntry{
							{Name: "root.txt", Path: "/from/root.txt", Size: 4},
							{Name: "nested", Path: "/from/nested", IsDir: true},
						},
					}, nil
				case "/from/nested":
					return &SFTPListResponse{
						Entries: []SFTPEntry{
							{Name: "child.txt", Path: "/from/nested/child.txt", Size: 5},
						},
					}, nil
				default:
					return &SFTPListResponse{}, nil
				}
			},
			sftpFetchChunkHook: func(req SFTPFetchChunkRequest) (*SFTPFetchChunkResponse, error) {
				mu.Lock()
				fetches = append(fetches, req)
				mu.Unlock()

				var (
					data []byte
					mode uint32
				)
				switch req.Path {
				case "/from/root.txt":
					data = []byte("root")
					mode = 0o100640
				case "/from/nested/child.txt":
					data = []byte("child")
					mode = 0o100600
				default:
					return nil, nil
				}

				if req.Offset >= int64(len(data)) {
					return &SFTPFetchChunkResponse{Path: req.Path, Offset: req.Offset, EOF: true, TotalSize: int64(len(data)), Mode: mode}, nil
				}
				end := req.Offset + int64(req.Length)
				if end > int64(len(data)) {
					end = int64(len(data))
				}
				chunk := append([]byte(nil), data[req.Offset:end]...)
				return &SFTPFetchChunkResponse{
					Path:      req.Path,
					Offset:    req.Offset,
					Data:      chunk,
					EOF:       end >= int64(len(data)),
					TotalSize: int64(len(data)),
					Mode:      mode,
				}, nil
			},
			sftpDeleteHook: func(req SFTPDeleteRequest) (*SFTPDeleteResponse, error) {
				mu.Lock()
				deletes = append(deletes, req)
				mu.Unlock()
				return &SFTPDeleteResponse{Path: req.Path, Removed: true}, nil
			},
		}
		destinationRPC = &stubNamespaceService{
			sftpPushChunkHook: func(req SFTPPushChunkRequest) (*SFTPPushChunkResponse, error) {
				mu.Lock()
				pushes = append(pushes, req)
				mu.Unlock()
				return &SFTPPushChunkResponse{Path: req.Path, Offset: req.Offset, BytesWritten: int64(len(req.Data))}, nil
			},
		}
	)
	sftpSyncChunkSize = 2
	defer func() {
		sftpSyncChunkSize = originalChunkSize
	}()

	plugins := []*runningPlugin{
		{cfg: NSConfig{Name: "srcns"}, rpc: sourceRPC},
		{cfg: NSConfig{Name: "dstns"}, rpc: destinationRPC},
	}
	dbPath := filepath.Join(t.TempDir(), sftpJobsDBFilename)
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
			Port:      2222,
			Username:  "dest",
			Password:  "dest-pass",
			Directory: "/to",
		},
		Interval: 24 * time.Hour,
	})
	if err != nil {
		t.Fatalf("CreateJob failed: %v", err)
	}
	if job.Enabled {
		t.Fatalf("new job should start disabled: %+v", job)
	}

	snapshot, err := manager.Snapshot()
	if err != nil {
		t.Fatalf("Snapshot failed: %v", err)
	}
	if len(snapshot) != 1 || snapshot[0].Enabled {
		t.Fatalf("unexpected initial snapshot: %+v", snapshot)
	}

	if _, err := manager.StartJob(job.ID); err != nil {
		t.Fatalf("StartJob failed: %v", err)
	}

	waitForJobSnapshot(t, manager, job.ID, func(view hostSFTPSyncJobView) bool {
		return view.Enabled && view.Running && view.LastStatus == "success" && view.LastFilesCopied == 2
	})

	mu.Lock()
	gotPushes := append([]SFTPPushChunkRequest(nil), pushes...)
	gotFetches := append([]SFTPFetchChunkRequest(nil), fetches...)
	gotDeletes := append([]SFTPDeleteRequest(nil), deletes...)
	mu.Unlock()

	if len(gotFetches) != 5 {
		t.Fatalf("unexpected fetch requests: %+v", gotFetches)
	}
	if len(gotPushes) != 5 {
		t.Fatalf("unexpected push requests: %+v", gotPushes)
	}
	if gotPushes[0].Path != "/to/root.txt" || gotPushes[2].Path != "/to/nested/child.txt" {
		t.Fatalf("unexpected push paths: %+v", gotPushes)
	}
	if !gotPushes[0].CreateParents || gotPushes[1].CreateParents || !gotPushes[2].CreateParents || gotPushes[3].CreateParents {
		t.Fatalf("unexpected CreateParents flags for chunk pushes: %+v", gotPushes)
	}
	if !gotPushes[0].Truncate || gotPushes[1].Truncate || !gotPushes[2].Truncate || gotPushes[3].Truncate {
		t.Fatalf("unexpected Truncate flags for chunk pushes: %+v", gotPushes)
	}
	if gotPushes[0].Offset != 0 || gotPushes[1].Offset != 2 || gotPushes[2].Offset != 0 || gotPushes[3].Offset != 2 || gotPushes[4].Offset != 4 {
		t.Fatalf("unexpected push offsets: %+v", gotPushes)
	}
	if len(gotDeletes) != 2 {
		t.Fatalf("unexpected delete requests: %+v", gotDeletes)
	}
	if gotDeletes[0].Path != "/from/root.txt" || gotDeletes[1].Path != "/from/nested/child.txt" {
		t.Fatalf("unexpected delete paths: %+v", gotDeletes)
	}
	if gotDeletes[0].Recursive || gotDeletes[1].Recursive {
		t.Fatalf("expected file deletes, got recursive requests: %+v", gotDeletes)
	}

	if _, err := manager.StopJob(job.ID); err != nil {
		t.Fatalf("StopJob failed: %v", err)
	}

	waitForJobSnapshot(t, manager, job.ID, func(view hostSFTPSyncJobView) bool {
		return !view.Enabled && !view.Running
	})

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
	snapshot, err = manager2.Snapshot()
	if err != nil {
		t.Fatalf("reloaded Snapshot failed: %v", err)
	}
	if len(snapshot) != 1 || snapshot[0].ID != job.ID || snapshot[0].Enabled || snapshot[0].Running {
		t.Fatalf("unexpected reloaded snapshot: %+v", snapshot)
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
			Port:      22,
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
	if len(snapshot) != 1 || snapshot[0].ID != job.ID || snapshot[0].FromAddress != "10.0.0.1:22" || snapshot[0].ToAddress != "10.0.0.2:22" || snapshot[0].Interval != "5m0s" {
		t.Fatalf("unexpected persisted snapshot: %+v", snapshot)
	}
}

func TestSFTPSyncJobManagerDeleteStopsRunnerAndRemovesJob(t *testing.T) {
	plugins := []*runningPlugin{
		{cfg: NSConfig{Name: "srcns"}, rpc: &stubNamespaceService{}},
		{cfg: NSConfig{Name: "dstns"}, rpc: &stubNamespaceService{}},
	}
	dbPath := filepath.Join(t.TempDir(), sftpJobsDBFilename)
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

	deleted, err := manager.DeleteJob(job.ID)
	if err != nil {
		t.Fatalf("DeleteJob failed: %v", err)
	}
	if deleted.ID != job.ID || deleted.From.Namespace != "srcns" || deleted.To.Namespace != "dstns" {
		t.Fatalf("unexpected deleted job: %+v", deleted)
	}

	manager.mu.Lock()
	_, exists := manager.runners[job.ID]
	manager.mu.Unlock()
	if exists {
		t.Fatalf("runner for deleted job %d still registered", job.ID)
	}

	snapshot, err := manager.Snapshot()
	if err != nil {
		t.Fatalf("Snapshot failed: %v", err)
	}
	if len(snapshot) != 0 {
		t.Fatalf("expected deleted job to be absent from snapshot, got %+v", snapshot)
	}

	if _, err := manager.DeleteJob(job.ID); err == nil || !strings.Contains(err.Error(), "not found") {
		t.Fatalf("expected deleting missing job to fail with not found, got %v", err)
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

	snapshot, err = manager2.Snapshot()
	if err != nil {
		t.Fatalf("reloaded Snapshot failed: %v", err)
	}
	if len(snapshot) != 0 {
		t.Fatalf("expected deleted job to stay deleted after reopen, got %+v", snapshot)
	}
}

func TestStreamSFTPFileDeletesSourceOnlyAfterSuccessfulPush(t *testing.T) {
	var (
		mu     sync.Mutex
		calls  []string
		source = &stubNamespaceService{
			sftpFetchChunkHook: func(req SFTPFetchChunkRequest) (*SFTPFetchChunkResponse, error) {
				mu.Lock()
				calls = append(calls, "fetch")
				mu.Unlock()
				if req.Offset > 0 {
					return &SFTPFetchChunkResponse{Path: req.Path, Offset: req.Offset, EOF: true, TotalSize: 2, Mode: 0o100600}, nil
				}
				return &SFTPFetchChunkResponse{
					Path:      req.Path,
					Offset:    0,
					Data:      []byte("ok"),
					EOF:       true,
					TotalSize: 2,
					Mode:      0o100600,
				}, nil
			},
			sftpDeleteHook: func(req SFTPDeleteRequest) (*SFTPDeleteResponse, error) {
				mu.Lock()
				calls = append(calls, "delete")
				mu.Unlock()
				return &SFTPDeleteResponse{Path: req.Path, Removed: true}, nil
			},
		}
		destination = &stubNamespaceService{
			sftpPushChunkHook: func(req SFTPPushChunkRequest) (*SFTPPushChunkResponse, error) {
				mu.Lock()
				calls = append(calls, "push")
				mu.Unlock()
				return &SFTPPushChunkResponse{Path: req.Path, Offset: req.Offset, BytesWritten: int64(len(req.Data))}, nil
			},
		}
	)

	if err := streamSFTPFile(
		source,
		destination,
		sftpEndpointConfig{Host: "10.0.0.1", Port: 22, Username: "src", Password: "pw"},
		sftpEndpointConfig{Host: "10.0.0.2", Port: 22, Username: "dst", Password: "pw"},
		"/from/demo.txt",
		"/to/demo.txt",
		2,
		0o100600,
	); err != nil {
		t.Fatalf("streamSFTPFile failed: %v", err)
	}

	mu.Lock()
	gotCalls := append([]string(nil), calls...)
	mu.Unlock()
	if strings.Join(gotCalls, ",") != "fetch,push,delete" {
		t.Fatalf("unexpected call order: %+v", gotCalls)
	}
}

func TestStreamSFTPFileDoesNotDeleteSourceOnPushFailure(t *testing.T) {
	pushErr := errors.New("synthetic push failure")
	var (
		mu     sync.Mutex
		calls  []string
		source = &stubNamespaceService{
			sftpFetchChunkHook: func(req SFTPFetchChunkRequest) (*SFTPFetchChunkResponse, error) {
				mu.Lock()
				calls = append(calls, "fetch")
				mu.Unlock()
				return &SFTPFetchChunkResponse{
					Path:      req.Path,
					Offset:    req.Offset,
					Data:      []byte("ok"),
					EOF:       true,
					TotalSize: 2,
					Mode:      0o100600,
				}, nil
			},
			sftpDeleteHook: func(req SFTPDeleteRequest) (*SFTPDeleteResponse, error) {
				mu.Lock()
				calls = append(calls, "delete")
				mu.Unlock()
				return &SFTPDeleteResponse{Path: req.Path, Removed: true}, nil
			},
		}
		destination = &stubNamespaceService{
			sftpPushChunkHook: func(req SFTPPushChunkRequest) (*SFTPPushChunkResponse, error) {
				mu.Lock()
				calls = append(calls, "push")
				mu.Unlock()
				return nil, pushErr
			},
		}
	)

	err := streamSFTPFile(
		source,
		destination,
		sftpEndpointConfig{Host: "10.0.0.1", Port: 22, Username: "src", Password: "pw"},
		sftpEndpointConfig{Host: "10.0.0.2", Port: 22, Username: "dst", Password: "pw"},
		"/from/demo.txt",
		"/to/demo.txt",
		2,
		0o100600,
	)
	if err == nil {
		t.Fatal("expected streamSFTPFile to fail")
	}
	if !strings.Contains(err.Error(), "push destination chunk") {
		t.Fatalf("unexpected error: %v", err)
	}

	mu.Lock()
	gotCalls := append([]string(nil), calls...)
	mu.Unlock()
	if strings.Join(gotCalls, ",") != "fetch,push" {
		t.Fatalf("unexpected call order: %+v", gotCalls)
	}
}

func TestHostDashboardServiceSFTPJobRoutes(t *testing.T) {
	var (
		originalChunkSize = sftpSyncChunkSize
		mu                sync.Mutex
		pushes            []SFTPPushChunkRequest
		deletes           []SFTPDeleteRequest
	)
	sftpSyncChunkSize = 2
	defer func() {
		sftpSyncChunkSize = originalChunkSize
	}()

	sourceRPC := &stubNamespaceService{
		sftpListHook: func(req SFTPListRequest) (*SFTPListResponse, error) {
			return &SFTPListResponse{
				Entries: []SFTPEntry{
					{Name: "demo.txt", Path: "/from/demo.txt", Size: 4},
				},
			}, nil
		},
		sftpFetchChunkHook: func(req SFTPFetchChunkRequest) (*SFTPFetchChunkResponse, error) {
			data := []byte("demo")
			if req.Offset >= int64(len(data)) {
				return &SFTPFetchChunkResponse{Path: req.Path, Offset: req.Offset, EOF: true, TotalSize: int64(len(data)), Mode: 0o100600}, nil
			}
			end := req.Offset + int64(req.Length)
			if end > int64(len(data)) {
				end = int64(len(data))
			}
			return &SFTPFetchChunkResponse{
				Path:      req.Path,
				Offset:    req.Offset,
				Data:      append([]byte(nil), data[req.Offset:end]...),
				EOF:       end >= int64(len(data)),
				TotalSize: int64(len(data)),
				Mode:      0o100600,
			}, nil
		},
		sftpDeleteHook: func(req SFTPDeleteRequest) (*SFTPDeleteResponse, error) {
			mu.Lock()
			deletes = append(deletes, req)
			mu.Unlock()
			return &SFTPDeleteResponse{Path: req.Path, Removed: true}, nil
		},
	}
	destinationRPC := &stubNamespaceService{
		sftpPushChunkHook: func(req SFTPPushChunkRequest) (*SFTPPushChunkResponse, error) {
			mu.Lock()
			pushes = append(pushes, req)
			mu.Unlock()
			return &SFTPPushChunkResponse{Path: req.Path, Offset: req.Offset, BytesWritten: int64(len(req.Data))}, nil
		},
	}

	plugins := []*runningPlugin{
		{
			cfg: NSConfig{Name: "srcns"},
			rpc: sourceRPC,
		},
		{
			cfg: NSConfig{Name: "dstns"},
			rpc: destinationRPC,
		},
	}
	manager, err := openSFTPSyncJobManager(filepath.Join(t.TempDir(), sftpJobsDBFilename), func(namespace string) *runningPlugin {
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
		persistentBase: "/data/netforge",
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
	if !strings.Contains(startRec.Body.String(), "Started SFTP sync job #1") {
		t.Fatalf("expected start success message, got %s", startRec.Body.String())
	}

	waitForJobSnapshot(t, manager, 1, func(view hostSFTPSyncJobView) bool {
		return view.Enabled && view.Running && view.LastStatus == "success"
	})
	mu.Lock()
	gotPushCount := len(pushes)
	gotDeleteCount := len(deletes)
	mu.Unlock()
	if gotPushCount == 0 {
		t.Fatal("expected scheduled job to push at least one file")
	}
	if gotDeleteCount == 0 {
		t.Fatal("expected scheduled job to delete source files after push")
	}

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

	waitForJobSnapshot(t, manager, 1, func(view hostSFTPSyncJobView) bool {
		return !view.Enabled && !view.Running
	})

	deleteReq := httptest.NewRequest(http.MethodPost, "/sftp-jobs/delete", strings.NewReader(startForm.Encode()))
	deleteReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	deleteRec := httptest.NewRecorder()
	service.routes().ServeHTTP(deleteRec, deleteReq)

	if deleteRec.Code != http.StatusOK {
		t.Fatalf("unexpected delete status code: got %d want %d", deleteRec.Code, http.StatusOK)
	}
	if !strings.Contains(deleteRec.Body.String(), "Deleted SFTP sync job #1") {
		t.Fatalf("expected delete success message, got %s", deleteRec.Body.String())
	}
	if !strings.Contains(deleteRec.Body.String(), "no jobs configured") {
		t.Fatalf("expected empty job table after delete, got %s", deleteRec.Body.String())
	}

	snapshot, err := manager.Snapshot()
	if err != nil {
		t.Fatalf("Snapshot after delete failed: %v", err)
	}
	if len(snapshot) != 0 {
		t.Fatalf("expected no jobs after delete, got %+v", snapshot)
	}

	wrongMethodReq := httptest.NewRequest(http.MethodGet, "/sftp-jobs/create", nil)
	wrongMethodRec := httptest.NewRecorder()
	service.routes().ServeHTTP(wrongMethodRec, wrongMethodReq)
	if wrongMethodRec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("unexpected wrong method status code: got %d want %d", wrongMethodRec.Code, http.StatusMethodNotAllowed)
	}
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
