//go:build linux

package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/google/nftables"
	"github.com/google/nftables/binaryutil"
	"github.com/google/nftables/expr"
	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netns"
	"golang.org/x/sys/unix"
)

type stubNamespaceService struct {
	describe           *DescribeResponse
	describeErr        error
	start              *StartHTTPResponse
	startErr           error
	checkTCPOutput     string
	checkTCPErr        error
	sftpListHook       func(SFTPListRequest) (*SFTPListResponse, error)
	sftpFetchHook      func(SFTPFetchRequest) (*SFTPFetchResponse, error)
	sftpFetchChunkHook func(SFTPFetchChunkRequest) (*SFTPFetchChunkResponse, error)
	sftpPushHook       func(SFTPPushRequest) (*SFTPPushResponse, error)
	sftpPushChunkHook  func(SFTPPushChunkRequest) (*SFTPPushChunkResponse, error)
	sftpDeleteHook     func(SFTPDeleteRequest) (*SFTPDeleteResponse, error)
	sftpList           *SFTPListResponse
	sftpListErr        error
	sftpFetch          *SFTPFetchResponse
	sftpFetchErr       error
	sftpFetchChunk     *SFTPFetchChunkResponse
	sftpFetchChunkErr  error
	sftpPush           *SFTPPushResponse
	sftpPushErr        error
	sftpPushChunk      *SFTPPushChunkResponse
	sftpPushChunkErr   error
	sftpDelete         *SFTPDeleteResponse
	sftpDeleteErr      error
	stopErr            error
	status             *StatusResponse
	statusErr          error
}

func (s *stubNamespaceService) Describe() (*DescribeResponse, error) {
	if s.describeErr != nil {
		return nil, s.describeErr
	}
	if s.describe == nil {
		return &DescribeResponse{}, nil
	}
	return s.describe, nil
}

func (s *stubNamespaceService) StartHTTP(port int) (*StartHTTPResponse, error) {
	if s.startErr != nil {
		return nil, s.startErr
	}
	if s.start != nil {
		return s.start, nil
	}
	return &StartHTTPResponse{HTTPAddr: fmt.Sprintf(":%d", port)}, nil
}

func (s *stubNamespaceService) CheckTCPPort(targetIP string, port int) (string, error) {
	if s.checkTCPErr != nil {
		return s.checkTCPOutput, s.checkTCPErr
	}
	if s.checkTCPOutput != "" {
		return s.checkTCPOutput, nil
	}
	return fmt.Sprintf("tcp connect to %s succeeded", net.JoinHostPort(targetIP, fmt.Sprintf("%d", port))), nil
}

func (s *stubNamespaceService) SFTPList(req SFTPListRequest) (*SFTPListResponse, error) {
	if s.sftpListHook != nil {
		return s.sftpListHook(req)
	}
	if s.sftpListErr != nil {
		return nil, s.sftpListErr
	}
	if s.sftpList != nil {
		return s.sftpList, nil
	}
	return &SFTPListResponse{}, nil
}

func (s *stubNamespaceService) SFTPFetch(req SFTPFetchRequest) (*SFTPFetchResponse, error) {
	if s.sftpFetchHook != nil {
		return s.sftpFetchHook(req)
	}
	if s.sftpFetchErr != nil {
		return nil, s.sftpFetchErr
	}
	if s.sftpFetch != nil {
		return s.sftpFetch, nil
	}
	return &SFTPFetchResponse{Path: req.Path}, nil
}

func (s *stubNamespaceService) SFTPFetchChunk(req SFTPFetchChunkRequest) (*SFTPFetchChunkResponse, error) {
	if s.sftpFetchChunkHook != nil {
		return s.sftpFetchChunkHook(req)
	}
	if s.sftpFetchChunkErr != nil {
		return nil, s.sftpFetchChunkErr
	}
	if s.sftpFetchChunk != nil {
		return s.sftpFetchChunk, nil
	}
	return &SFTPFetchChunkResponse{Path: req.Path, Offset: req.Offset, EOF: true}, nil
}

func (s *stubNamespaceService) SFTPPush(req SFTPPushRequest) (*SFTPPushResponse, error) {
	if s.sftpPushHook != nil {
		return s.sftpPushHook(req)
	}
	if s.sftpPushErr != nil {
		return nil, s.sftpPushErr
	}
	if s.sftpPush != nil {
		return s.sftpPush, nil
	}
	return &SFTPPushResponse{Path: req.Path, BytesWritten: int64(len(req.Data))}, nil
}

func (s *stubNamespaceService) SFTPPushChunk(req SFTPPushChunkRequest) (*SFTPPushChunkResponse, error) {
	if s.sftpPushChunkHook != nil {
		return s.sftpPushChunkHook(req)
	}
	if s.sftpPushChunkErr != nil {
		return nil, s.sftpPushChunkErr
	}
	if s.sftpPushChunk != nil {
		return s.sftpPushChunk, nil
	}
	return &SFTPPushChunkResponse{Path: req.Path, Offset: req.Offset, BytesWritten: int64(len(req.Data))}, nil
}

func (s *stubNamespaceService) SFTPDelete(req SFTPDeleteRequest) (*SFTPDeleteResponse, error) {
	if s.sftpDeleteHook != nil {
		return s.sftpDeleteHook(req)
	}
	if s.sftpDeleteErr != nil {
		return nil, s.sftpDeleteErr
	}
	if s.sftpDelete != nil {
		return s.sftpDelete, nil
	}
	return &SFTPDeleteResponse{Path: req.Path, Removed: true}, nil
}

func (s *stubNamespaceService) StopHTTP() error {
	if s.stopErr != nil {
		return s.stopErr
	}
	return nil
}

func (s *stubNamespaceService) Status() (*StatusResponse, error) {
	if s.statusErr != nil {
		return nil, s.statusErr
	}
	if s.status == nil {
		return &StatusResponse{}, nil
	}
	return s.status, nil
}

type delayedNamespaceService struct {
	describeWait <-chan struct{}
	describe     *DescribeResponse
	describeErr  error
	statusWait   <-chan struct{}
	status       *StatusResponse
	statusErr    error
}

func (s *delayedNamespaceService) Describe() (*DescribeResponse, error) {
	if s.describeWait != nil {
		<-s.describeWait
	}
	if s.describeErr != nil {
		return nil, s.describeErr
	}
	if s.describe == nil {
		return &DescribeResponse{}, nil
	}
	return s.describe, nil
}

func (s *delayedNamespaceService) StartHTTP(port int) (*StartHTTPResponse, error) {
	return &StartHTTPResponse{HTTPAddr: fmt.Sprintf(":%d", port)}, nil
}

func (s *delayedNamespaceService) CheckTCPPort(targetIP string, port int) (string, error) {
	return fmt.Sprintf("tcp connect to %s succeeded", net.JoinHostPort(targetIP, fmt.Sprintf("%d", port))), nil
}

func (s *delayedNamespaceService) SFTPList(req SFTPListRequest) (*SFTPListResponse, error) {
	return &SFTPListResponse{}, nil
}

func (s *delayedNamespaceService) SFTPFetch(req SFTPFetchRequest) (*SFTPFetchResponse, error) {
	return &SFTPFetchResponse{Path: req.Path}, nil
}

func (s *delayedNamespaceService) SFTPFetchChunk(req SFTPFetchChunkRequest) (*SFTPFetchChunkResponse, error) {
	return &SFTPFetchChunkResponse{Path: req.Path, Offset: req.Offset, EOF: true}, nil
}

func (s *delayedNamespaceService) SFTPPush(req SFTPPushRequest) (*SFTPPushResponse, error) {
	return &SFTPPushResponse{Path: req.Path, BytesWritten: int64(len(req.Data))}, nil
}

func (s *delayedNamespaceService) SFTPPushChunk(req SFTPPushChunkRequest) (*SFTPPushChunkResponse, error) {
	return &SFTPPushChunkResponse{Path: req.Path, Offset: req.Offset, BytesWritten: int64(len(req.Data))}, nil
}

func (s *delayedNamespaceService) SFTPDelete(req SFTPDeleteRequest) (*SFTPDeleteResponse, error) {
	return &SFTPDeleteResponse{Path: req.Path, Removed: true}, nil
}

func (s *delayedNamespaceService) StopHTTP() error {
	return nil
}

func (s *delayedNamespaceService) Status() (*StatusResponse, error) {
	if s.statusWait != nil {
		<-s.statusWait
	}
	if s.statusErr != nil {
		return nil, s.statusErr
	}
	if s.status == nil {
		return &StatusResponse{}, nil
	}
	return s.status, nil
}

type fakeNamespacePinger struct {
	network    string
	privileged bool
	count      int
	interval   time.Duration
	timeout    time.Duration
	onRecv     func(namespacePingPacket)
	runErr     error
	stats      namespacePingStats
}

func (p *fakeNamespacePinger) SetNetwork(network string) {
	p.network = network
}

func (p *fakeNamespacePinger) SetPrivileged(privileged bool) {
	p.privileged = privileged
}

func (p *fakeNamespacePinger) SetCount(count int) {
	p.count = count
}

func (p *fakeNamespacePinger) SetInterval(interval time.Duration) {
	p.interval = interval
}

func (p *fakeNamespacePinger) SetTimeout(timeout time.Duration) {
	p.timeout = timeout
}

func (p *fakeNamespacePinger) SetOnRecv(handler func(namespacePingPacket)) {
	p.onRecv = handler
}

func (p *fakeNamespacePinger) Run() error {
	if p.onRecv != nil && p.stats.PacketsRecv > 0 {
		p.onRecv(namespacePingPacket{
			NBytes: 64,
			IPAddr: p.stats.IPAddr,
			Seq:    1,
			Rtt:    p.stats.AvgRtt,
		})
	}
	return p.runErr
}

func (p *fakeNamespacePinger) Statistics() namespacePingStats {
	return p.stats
}

func restorePingTestHooks() func() {
	originalRunInNamedNamespace := runInNamedNamespace
	originalNewNamespacePinger := newNamespacePinger
	return func() {
		runInNamedNamespace = originalRunInNamedNamespace
		newNamespacePinger = originalNewNamespacePinger
	}
}

func TestPluginConfigJSONRoundTrip(t *testing.T) {
	cfg := NSConfig{
		Name:       "nsx",
		VLANID:     42,
		IfName:     "eth0.42",
		IPCIDR:     "192.0.2.10/24",
		MAC:        "02:00:00:00:42:42",
		Gateway:    "192.0.2.1",
		ListenPort: 8080,
		OpenPorts:  []int{9090, 9443},
		AllowICMP:  true,
	}

	raw, err := pluginConfigJSON(cfg)
	if err != nil {
		t.Fatalf("pluginConfigJSON failed: %v", err)
	}

	t.Setenv("NS_PLUGIN_CONFIG", raw)
	got, err := loadPluginConfigFromEnv()
	if err != nil {
		t.Fatalf("loadPluginConfigFromEnv failed: %v", err)
	}

	if got.Namespace != cfg.Name {
		t.Fatalf("namespace mismatch: got %q want %q", got.Namespace, cfg.Name)
	}
	if got.Interface != cfg.IfName {
		t.Fatalf("interface mismatch: got %q want %q", got.Interface, cfg.IfName)
	}
	if got.IPCIDR != cfg.IPCIDR {
		t.Fatalf("ip mismatch: got %q want %q", got.IPCIDR, cfg.IPCIDR)
	}
	if got.MAC != cfg.MAC {
		t.Fatalf("mac mismatch: got %q want %q", got.MAC, cfg.MAC)
	}
	if got.Gateway != cfg.Gateway {
		t.Fatalf("gateway mismatch: got %q want %q", got.Gateway, cfg.Gateway)
	}
	if !reflect.DeepEqual(got.OpenPorts, cfg.OpenPorts) {
		t.Fatalf("open ports mismatch: got %v want %v", got.OpenPorts, cfg.OpenPorts)
	}
	if got.AllowICMP != cfg.AllowICMP {
		t.Fatalf("allow icmp mismatch: got %t want %t", got.AllowICMP, cfg.AllowICMP)
	}
}

func TestLoadPluginConfigFromEnvRejectsInvalidNamespaceName(t *testing.T) {
	t.Setenv("NS_PLUGIN_CONFIG", `{"namespace":"../escape","interface":"eth0.42","ip_cidr":"192.0.2.10/24","open_ports":[8080]}`)

	_, err := loadPluginConfigFromEnv()
	if err == nil {
		t.Fatal("loadPluginConfigFromEnv succeeded, want error")
	}
	if !strings.Contains(err.Error(), `invalid namespace name "../escape"`) {
		t.Fatalf("loadPluginConfigFromEnv error = %v, want invalid namespace name", err)
	}
}

func TestConfigHelpers(t *testing.T) {
	t.Run("envDefault", func(t *testing.T) {
		if got := envDefault("NETFORGE_TEST_ENV_DEFAULT", "fallback"); got != "fallback" {
			t.Fatalf("unexpected fallback value: got %q want %q", got, "fallback")
		}

		t.Setenv("NETFORGE_TEST_ENV_DEFAULT", "present")
		if got := envDefault("NETFORGE_TEST_ENV_DEFAULT", "fallback"); got != "present" {
			t.Fatalf("unexpected env value: got %q want %q", got, "present")
		}
	})

	t.Run("defaultConfigs", func(t *testing.T) {
		cfgs := defaultConfigs("eth9")
		if len(cfgs) != 2 {
			t.Fatalf("unexpected default config count: got %d want %d", len(cfgs), 2)
		}
		if cfgs[0].IfName != "eth9.1" || cfgs[1].IfName != "eth9.2" {
			t.Fatalf("unexpected default interfaces: %+v", cfgs)
		}
		if !reflect.DeepEqual(cfgs[0].OpenPorts, []int{cfgs[0].ListenPort}) || !reflect.DeepEqual(cfgs[1].OpenPorts, []int{cfgs[1].ListenPort}) {
			t.Fatalf("expected default open ports to match listen ports: %+v", cfgs)
		}
	})

	t.Run("loadConfigs default", func(t *testing.T) {
		t.Setenv("NS_CONFIG_JSON", "")
		cfgs, err := loadConfigs("eth7")
		if err != nil {
			t.Fatalf("loadConfigs default failed: %v", err)
		}
		if len(cfgs) != 2 || cfgs[0].IfName != "eth7.1" || cfgs[1].IfName != "eth7.2" {
			t.Fatalf("unexpected default configs: %+v", cfgs)
		}
	})

	t.Run("loadConfigs custom", func(t *testing.T) {
		t.Setenv("NS_CONFIG_JSON", `[{"name":"nsx","listen_port":8088,"allow_icmp":true}]`)
		cfgs, err := loadConfigs("ignored0")
		if err != nil {
			t.Fatalf("loadConfigs custom failed: %v", err)
		}
		if len(cfgs) != 1 {
			t.Fatalf("unexpected config count: got %d want %d", len(cfgs), 1)
		}
		if !reflect.DeepEqual(cfgs[0].OpenPorts, []int{8088}) {
			t.Fatalf("expected open_ports default from listen_port: %+v", cfgs[0])
		}
		if !cfgs[0].AllowICMP {
			t.Fatalf("expected allow_icmp=true: %+v", cfgs[0])
		}
	})

	t.Run("loadConfigs explicit empty open ports", func(t *testing.T) {
		t.Setenv("NS_CONFIG_JSON", `[{"name":"nsx","listen_port":8088,"open_ports":[]}]`)
		cfgs, err := loadConfigs("ignored0")
		if err != nil {
			t.Fatalf("loadConfigs explicit empty open ports failed: %v", err)
		}
		if len(cfgs) != 1 {
			t.Fatalf("unexpected config count: got %d want %d", len(cfgs), 1)
		}
		if !reflect.DeepEqual(cfgs[0].OpenPorts, []int{}) {
			t.Fatalf("expected explicit empty open ports to be preserved: %+v", cfgs[0])
		}
	})

	t.Run("loadConfigs invalid", func(t *testing.T) {
		t.Setenv("NS_CONFIG_JSON", `not-json`)
		if _, err := loadConfigs("eth0"); err == nil {
			t.Fatal("expected invalid json error")
		}
	})

	t.Run("loadConfigs empty", func(t *testing.T) {
		t.Setenv("NS_CONFIG_JSON", `[]`)
		if _, err := loadConfigs("eth0"); err == nil {
			t.Fatal("expected empty config error")
		}
	})
}

func TestNamespaceServicePluginServerRPCWrappers(t *testing.T) {
	stub := &stubNamespaceService{
		describe: &DescribeResponse{
			Namespace: "ns-rpc",
			HTTPAddr:  ":19090",
			Message:   "plugin ready",
		},
		start:          &StartHTTPResponse{HTTPAddr: ":19090"},
		checkTCPOutput: "tcp connect to 192.0.2.10:19090 from ns-rpc succeeded",
		sftpList: &SFTPListResponse{
			Entries: []SFTPEntry{
				{Name: "demo.txt", Path: "/demo.txt", Size: 4, Mode: 0o100644, IsDir: false, ModTimeUnix: 1234},
			},
		},
		sftpFetch: &SFTPFetchResponse{
			Path:        "/demo.txt",
			Data:        []byte("demo"),
			Size:        4,
			Mode:        0o100644,
			ModTimeUnix: 1234,
		},
		sftpFetchChunk: &SFTPFetchChunkResponse{
			Path:      "/demo.txt",
			Offset:    2,
			Data:      []byte("mo"),
			EOF:       true,
			TotalSize: 4,
			Mode:      0o100644,
		},
		sftpPush: &SFTPPushResponse{
			Path:         "/upload/demo.txt",
			BytesWritten: 5,
		},
		sftpPushChunk: &SFTPPushChunkResponse{
			Path:         "/upload/demo.txt",
			Offset:       2,
			BytesWritten: 2,
		},
		sftpDelete: &SFTPDeleteResponse{
			Path:    "/upload/demo.txt",
			Removed: true,
		},
		status: &StatusResponse{
			Namespace:   "ns-rpc",
			Interface:   "eth0.42",
			IPCIDR:      "192.0.2.10/24",
			MAC:         "02:00:00:00:42:42",
			Gateway:     "192.0.2.1",
			OpenPorts:   []int{19090, 19443},
			AllowICMP:   true,
			HTTPAddr:    ":19090",
			HTTPRunning: true,
		},
	}

	raw, err := (&namespaceServicePlugin{Impl: stub}).Server(nil)
	if err != nil {
		t.Fatalf("Server failed: %v", err)
	}

	server, ok := raw.(*namespaceServiceRPCServer)
	if !ok {
		t.Fatalf("unexpected server type: %T", raw)
	}

	var describe DescribeResponse
	if err := server.Describe(struct{}{}, &describe); err != nil {
		t.Fatalf("Describe failed: %v", err)
	}
	if describe.Namespace != "ns-rpc" || describe.HTTPAddr != ":19090" {
		t.Fatalf("unexpected describe response: %+v", describe)
	}

	var start StartHTTPResponse
	if err := server.StartHTTP(19090, &start); err != nil {
		t.Fatalf("StartHTTP failed: %v", err)
	}
	if start.HTTPAddr != ":19090" {
		t.Fatalf("unexpected start response: %+v", start)
	}

	var checkTCP string
	if err := server.CheckTCPPort(CheckTCPPortRequest{TargetIP: "192.0.2.10", Port: 19090}, &checkTCP); err != nil {
		t.Fatalf("CheckTCPPort failed: %v", err)
	}
	if checkTCP != "tcp connect to 192.0.2.10:19090 from ns-rpc succeeded" {
		t.Fatalf("unexpected CheckTCPPort response: %q", checkTCP)
	}

	var list SFTPListResponse
	if err := server.SFTPList(SFTPListRequest{Directory: "/"}, &list); err != nil {
		t.Fatalf("SFTPList failed: %v", err)
	}
	if len(list.Entries) != 1 || list.Entries[0].Path != "/demo.txt" {
		t.Fatalf("unexpected SFTPList response: %+v", list)
	}

	var fetch SFTPFetchResponse
	if err := server.SFTPFetch(SFTPFetchRequest{Path: "/demo.txt"}, &fetch); err != nil {
		t.Fatalf("SFTPFetch failed: %v", err)
	}
	if fetch.Path != "/demo.txt" || string(fetch.Data) != "demo" {
		t.Fatalf("unexpected SFTPFetch response: %+v", fetch)
	}

	var fetchChunk SFTPFetchChunkResponse
	if err := server.SFTPFetchChunk(SFTPFetchChunkRequest{Path: "/demo.txt", Offset: 2, Length: 2}, &fetchChunk); err != nil {
		t.Fatalf("SFTPFetchChunk failed: %v", err)
	}
	if fetchChunk.Path != "/demo.txt" || fetchChunk.Offset != 2 || string(fetchChunk.Data) != "mo" || !fetchChunk.EOF {
		t.Fatalf("unexpected SFTPFetchChunk response: %+v", fetchChunk)
	}

	var push SFTPPushResponse
	if err := server.SFTPPush(SFTPPushRequest{Path: "/upload/demo.txt", Data: []byte("hello")}, &push); err != nil {
		t.Fatalf("SFTPPush failed: %v", err)
	}
	if push.Path != "/upload/demo.txt" || push.BytesWritten != 5 {
		t.Fatalf("unexpected SFTPPush response: %+v", push)
	}

	var pushChunk SFTPPushChunkResponse
	if err := server.SFTPPushChunk(SFTPPushChunkRequest{Path: "/upload/demo.txt", Offset: 2, Data: []byte("lo")}, &pushChunk); err != nil {
		t.Fatalf("SFTPPushChunk failed: %v", err)
	}
	if pushChunk.Path != "/upload/demo.txt" || pushChunk.Offset != 2 || pushChunk.BytesWritten != 2 {
		t.Fatalf("unexpected SFTPPushChunk response: %+v", pushChunk)
	}

	var del SFTPDeleteResponse
	if err := server.SFTPDelete(SFTPDeleteRequest{Path: "/upload/demo.txt"}, &del); err != nil {
		t.Fatalf("SFTPDelete failed: %v", err)
	}
	if del.Path != "/upload/demo.txt" || !del.Removed {
		t.Fatalf("unexpected SFTPDelete response: %+v", del)
	}

	if err := server.StopHTTP(struct{}{}, &struct{}{}); err != nil {
		t.Fatalf("StopHTTP failed: %v", err)
	}

	var status StatusResponse
	if err := server.Status(struct{}{}, &status); err != nil {
		t.Fatalf("Status failed: %v", err)
	}
	if status.Namespace != "ns-rpc" || !status.HTTPRunning || !status.AllowICMP {
		t.Fatalf("unexpected status response: %+v", status)
	}
}

func TestNamespaceHTTPServiceLifecycle(t *testing.T) {
	svc := &namespaceHTTPService{cfg: PluginConfig{
		Namespace: "ns-test",
		Interface: "eth0.100",
		IPCIDR:    "192.0.2.10/24",
		MAC:       "02:00:00:00:10:10",
		Gateway:   "192.0.2.1",
		OpenPorts: []int{18080, 18443},
		AllowICMP: true,
	}}

	desc, err := svc.Describe()
	if err != nil {
		t.Fatalf("Describe failed: %v", err)
	}
	if desc.Namespace != "ns-test" || desc.Message != "plugin ready" || desc.HTTPAddr != "" {
		t.Fatalf("unexpected initial describe response: %+v", desc)
	}

	start, err := svc.StartHTTP(18080)
	if err != nil {
		t.Fatalf("StartHTTP failed: %v", err)
	}
	if start.HTTPAddr != ":18080" {
		t.Fatalf("unexpected http addr: %q", start.HTTPAddr)
	}

	desc, err = svc.Describe()
	if err != nil {
		t.Fatalf("Describe after start failed: %v", err)
	}
	if desc.HTTPAddr != ":18080" {
		t.Fatalf("unexpected describe addr after start: %+v", desc)
	}

	waitForHTTP(t, func() (string, int, error) {
		resp, err := http.Get("http://127.0.0.1:18080/")
		if err != nil {
			return "", 0, err
		}
		defer resp.Body.Close()
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			return "", 0, err
		}
		return string(body), resp.StatusCode, nil
	})

	status, err := svc.Status()
	if err != nil {
		t.Fatalf("Status failed: %v", err)
	}
	if !status.HTTPRunning {
		t.Fatal("expected HTTPRunning=true")
	}
	if !reflect.DeepEqual(status.OpenPorts, []int{18080, 18443}) {
		t.Fatalf("unexpected open ports: got %v want %v", status.OpenPorts, []int{18080, 18443})
	}
	if !status.AllowICMP {
		t.Fatal("expected AllowICMP=true")
	}

	resp, err := http.Get("http://127.0.0.1:18080/")
	if err != nil {
		t.Fatalf("GET / failed: %v", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("ReadAll failed: %v", err)
	}
	if !strings.Contains(string(body), "namespace=ns-test") {
		t.Fatalf("unexpected body: %s", string(body))
	}

	checkTCPOutput, err := svc.CheckTCPPort("127.0.0.1", 18080)
	if err != nil {
		t.Fatalf("CheckTCPPort failed: %v", err)
	}
	if !strings.Contains(checkTCPOutput, "tcp connect to 127.0.0.1:18080 from ns-test succeeded") {
		t.Fatalf("unexpected CheckTCPPort output: %q", checkTCPOutput)
	}

	if err := svc.StopHTTP(); err != nil {
		t.Fatalf("StopHTTP failed: %v", err)
	}

	status, err = svc.Status()
	if err != nil {
		t.Fatalf("Status after stop failed: %v", err)
	}
	if status.HTTPRunning {
		t.Fatal("expected HTTPRunning=false after stop")
	}
}

func TestStartHostDashboardAndRunHost(t *testing.T) {
	t.Run("dashboard server", func(t *testing.T) {
		server, addr, err := startHostDashboard("127.0.0.1:0", "eth0", "/var/lib/netforge", "/data/netforge", nil, nil)
		if err != nil {
			t.Fatalf("startHostDashboard failed: %v", err)
		}
		t.Cleanup(func() {
			shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			_ = server.Shutdown(shutdownCtx)
		})

		resp, err := http.Get("http://" + addr + "/healthz")
		if err != nil {
			t.Fatalf("GET /healthz failed: %v", err)
		}
		defer resp.Body.Close()
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatalf("ReadAll healthz failed: %v", err)
		}
		if resp.StatusCode != http.StatusOK || string(body) != "ok\n" {
			t.Fatalf("unexpected healthz response: code=%d body=%q", resp.StatusCode, string(body))
		}

		resp, err = http.Get("http://" + addr + "/api/namespaces")
		if err != nil {
			t.Fatalf("GET /api/namespaces failed: %v", err)
		}
		defer resp.Body.Close()
		var payload hostDashboardData
		if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
			t.Fatalf("decode api response failed: %v", err)
		}
		if len(payload.Namespaces) != 0 {
			t.Fatalf("expected no namespaces, got %+v", payload.Namespaces)
		}

		resp, err = http.Get("http://" + addr + "/does-not-exist")
		if err != nil {
			t.Fatalf("GET /does-not-exist failed: %v", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusNotFound {
			t.Fatalf("unexpected not found status: got %d want %d", resp.StatusCode, http.StatusNotFound)
		}
	})

	t.Run("runHost no configs", func(t *testing.T) {
		restore := restoreReconcileTestHooks()
		defer restore()

		hostLinkByName = func(name string) (netlink.Link, error) {
			link := &netlink.Dummy{LinkAttrs: netlink.NewLinkAttrs()}
			link.LinkAttrs.Name = name
			return link, nil
		}
		readDirEntries = func(string) ([]os.DirEntry, error) {
			return nil, os.ErrNotExist
		}
		destroyNamespaceLinks = func(string) error { return nil }
		deleteNamedNamespace = func(string) error { return nil }
		removeAllPath = func(string) error { return nil }

		ctx, cancel := context.WithCancel(context.Background())
		cancel()

		if err := runHost(ctx, "eth0", "/bin/true", t.TempDir(), t.TempDir(), "127.0.0.1:0", nil); err != nil {
			t.Fatalf("runHost failed: %v", err)
		}
	})
}

func TestNamespaceCmdRunnerHelpers(t *testing.T) {
	cmd := exec.Command("sleep", "30")
	if err := cmd.Start(); err != nil {
		t.Fatalf("cmd.Start failed: %v", err)
	}

	runner := &namespaceCmdRunner{
		cmd:       cmd,
		path:      cmd.Path,
		namespace: "ns-helper",
		sandbox: pluginSandboxSpec{
			hostSocketDir:   "/host/plugin-dir",
			hostDataDir:     "/host/plugin-data",
			pluginSocketDir: pluginSandboxSocketDir,
			pluginDataDir:   pluginSandboxDataDir,
		},
	}

	if got := runner.Diagnose(context.Background()); !strings.Contains(got, `network namespace "ns-helper"`) {
		t.Fatalf("unexpected diagnose output: %q", got)
	}

	pluginNet, pluginAddr, err := runner.PluginToHost("unix", "/tmp/plugin.sock")
	if err == nil {
		t.Fatalf("expected PluginToHost to reject unmapped unix socket, got %q %q", pluginNet, pluginAddr)
	}

	pluginNet, pluginAddr, err = runner.PluginToHost("unix", "/run/go-plugin/plugin.sock")
	if err != nil {
		t.Fatalf("PluginToHost failed: %v", err)
	}
	if pluginNet != "unix" || pluginAddr != "/host/plugin-dir/plugin.sock" {
		t.Fatalf("unexpected PluginToHost mapping: %q %q", pluginNet, pluginAddr)
	}

	hostNet, hostAddr, err := runner.HostToPlugin("tcp", "127.0.0.1:8080")
	if err != nil {
		t.Fatalf("HostToPlugin failed: %v", err)
	}
	if hostNet != "tcp" || hostAddr != "127.0.0.1:8080" {
		t.Fatalf("unexpected HostToPlugin mapping: %q %q", hostNet, hostAddr)
	}

	hostNet, hostAddr, err = runner.HostToPlugin("unix", "/host/plugin-dir/plugin.sock")
	if err != nil {
		t.Fatalf("HostToPlugin unix mapping failed: %v", err)
	}
	if hostNet != "unix" || hostAddr != "/run/go-plugin/plugin.sock" {
		t.Fatalf("unexpected HostToPlugin unix mapping: %q %q", hostNet, hostAddr)
	}

	if err := runner.Kill(context.Background()); err != nil {
		t.Fatalf("Kill failed: %v", err)
	}
	if _, err := cmd.Process.Wait(); err != nil {
		t.Fatalf("wait after kill failed: %v", err)
	}
}

func TestPingNamespaceAddressRejectsInvalidIP(t *testing.T) {
	if _, err := pingNamespaceAddress("ns1", "not-an-ip"); err == nil {
		t.Fatal("expected invalid ip error")
	}
}

func TestPingNamespaceAddressUsesGoPinger(t *testing.T) {
	restore := restorePingTestHooks()
	defer restore()

	var (
		gotNamespace string
		pinger       = &fakeNamespacePinger{
			stats: namespacePingStats{
				PacketsSent: 1,
				PacketsRecv: 1,
				PacketLoss:  0,
				Addr:        "192.0.2.1",
				IPAddr:      "192.0.2.1",
				MinRtt:      5 * time.Millisecond,
				AvgRtt:      5 * time.Millisecond,
				MaxRtt:      5 * time.Millisecond,
				StdDevRtt:   0,
			},
		}
	)

	runInNamedNamespace = func(namespaceName string, fn func() error) error {
		gotNamespace = namespaceName
		return fn()
	}
	newNamespacePinger = func(addr string) namespacePinger {
		if addr != "192.0.2.1" {
			t.Fatalf("newNamespacePinger addr = %q, want %q", addr, "192.0.2.1")
		}
		return pinger
	}

	output, err := pingNamespaceAddress("ns1", "192.0.2.1")
	if err != nil {
		t.Fatalf("pingNamespaceAddress failed: %v", err)
	}
	if gotNamespace != "ns1" {
		t.Fatalf("runInNamedNamespace namespace = %q, want %q", gotNamespace, "ns1")
	}
	if pinger.network != "ip4" {
		t.Fatalf("network = %q, want ip4", pinger.network)
	}
	if !pinger.privileged {
		t.Fatal("expected privileged ping mode")
	}
	if pinger.count != 1 {
		t.Fatalf("count = %d, want 1", pinger.count)
	}
	if pinger.timeout != 2*time.Second {
		t.Fatalf("timeout = %s, want %s", pinger.timeout, 2*time.Second)
	}
	if !strings.Contains(output, "1 packets transmitted, 1 packets received, 0% packet loss") {
		t.Fatalf("unexpected ping output: %s", output)
	}
	if !strings.Contains(output, "64 bytes from 192.0.2.1: icmp_seq=1") {
		t.Fatalf("unexpected ping recv output: %s", output)
	}
}

func TestPingNamespaceAddressTimeoutReturnsError(t *testing.T) {
	restore := restorePingTestHooks()
	defer restore()

	runInNamedNamespace = func(_ string, fn func() error) error {
		return fn()
	}
	newNamespacePinger = func(string) namespacePinger {
		return &fakeNamespacePinger{
			stats: namespacePingStats{
				PacketsSent: 1,
				PacketsRecv: 0,
				PacketLoss:  100,
				Addr:        "192.0.2.2",
			},
		}
	}

	output, err := pingNamespaceAddress("ns1", "192.0.2.2")
	if err == nil || err.Error() != "ping timed out" {
		t.Fatalf("pingNamespaceAddress error = %v, want ping timed out", err)
	}
	if !strings.Contains(output, "1 packets transmitted, 0 packets received, 100% packet loss") {
		t.Fatalf("unexpected timeout output: %s", output)
	}
}

func TestCheckCurrentNamespaceTCPPortRejectsInvalidInput(t *testing.T) {
	if _, err := checkCurrentNamespaceTCPPort("ns1", "not-an-ip", 80); err == nil {
		t.Fatal("expected invalid ip error")
	}
	if _, err := checkCurrentNamespaceTCPPort("ns1", "192.0.2.1", 0); err == nil {
		t.Fatal("expected invalid port error")
	}
}

func TestHostDashboardServiceCheckTCPPortUsesPluginRPC(t *testing.T) {
	service := &hostDashboardService{
		plugins: []*runningPlugin{
			{
				cfg: NSConfig{Name: "ns1"},
				rpc: &stubNamespaceService{
					checkTCPOutput: "tcp connect to 10.10.100.1:443 from ns1 succeeded",
				},
			},
		},
	}

	output, err := service.checkTCPPort("ns1", "10.10.100.1", 443)
	if err != nil {
		t.Fatalf("checkTCPPort failed: %v", err)
	}
	if output != "tcp connect to 10.10.100.1:443 from ns1 succeeded" {
		t.Fatalf("unexpected output: %q", output)
	}
}

func TestHostDashboardServiceListSFTPUsesPluginRPC(t *testing.T) {
	var gotReq SFTPListRequest
	service := &hostDashboardService{
		plugins: []*runningPlugin{
			{
				cfg: NSConfig{Name: "ns1"},
				rpc: &stubNamespaceService{
					sftpListHook: func(req SFTPListRequest) (*SFTPListResponse, error) {
						gotReq = req
						return &SFTPListResponse{
							Entries: []SFTPEntry{{Name: "demo.txt", Path: "/demo.txt", Size: 4}},
						}, nil
					},
				},
			},
		},
	}

	resp, err := service.listSFTP("ns1", SFTPListRequest{
		Connection: SFTPConnectionInfo{
			Address:               "10.10.100.1:22",
			Username:              "demo",
			Password:              "secret",
			InsecureIgnoreHostKey: true,
		},
		Directory: "/incoming",
	})
	if err != nil {
		t.Fatalf("listSFTP failed: %v", err)
	}
	if len(resp.Entries) != 1 || resp.Entries[0].Path != "/demo.txt" {
		t.Fatalf("unexpected response: %+v", resp)
	}
	if gotReq.Connection.Address != "10.10.100.1:22" || gotReq.Connection.Username != "demo" || gotReq.Connection.Password != "secret" || !gotReq.Connection.InsecureIgnoreHostKey || gotReq.Directory != "/incoming" {
		t.Fatalf("unexpected forwarded request: %+v", gotReq)
	}
}

func TestHostDashboardServiceRoutes(t *testing.T) {
	var pingCalls []string
	var tcpCheckCalls []string
	var sftpListCalls []SFTPListRequest
	service := &hostDashboardService{
		addr:           "127.0.0.1:8090",
		parentNIC:      "eth0",
		runtimeBase:    "/var/lib/netforge",
		persistentBase: "/data/netforge",
		statsLookup: func(namespaceName, ifName string) (hostNICStatisticsView, error) {
			switch namespaceName {
			case "ns1":
				return hostNICStatisticsView{
					RxBytes:   1024,
					TxBytes:   2048,
					RxPackets: 11,
					TxPackets: 22,
					RxErrors:  1,
					TxErrors:  2,
					RxDropped: 3,
					TxDropped: 4,
				}, nil
			case "ns2":
				return hostNICStatisticsView{}, errors.New("statistics unavailable")
			default:
				return hostNICStatisticsView{}, fmt.Errorf("unexpected namespace %q", namespaceName)
			}
		},
		arpLookup: func(namespaceName, ifName string) ([]hostARPEntryView, error) {
			switch namespaceName {
			case "ns1":
				return []hostARPEntryView{
					{IP: "10.10.100.1", MAC: "02:00:00:00:10:01"},
					{IP: "10.10.100.3", MAC: "02:00:00:00:10:03"},
				}, nil
			case "ns2":
				return nil, errors.New("arp unavailable")
			default:
				return nil, fmt.Errorf("unexpected namespace %q", namespaceName)
			}
		},
		pingFunc: func(namespaceName, targetIP string) (string, error) {
			pingCalls = append(pingCalls, namespaceName+"->"+targetIP)
			if namespaceName == "ns1" && targetIP == "10.10.100.1" {
				return "PING 10.10.100.1: 1 packets transmitted, 1 received", nil
			}
			return "PING failed", fmt.Errorf("ping %s from %s failed", targetIP, namespaceName)
		},
		tcpCheckFunc: func(namespaceName, targetIP string, port int) (string, error) {
			tcpCheckCalls = append(tcpCheckCalls, fmt.Sprintf("%s->%s:%d", namespaceName, targetIP, port))
			if namespaceName == "ns1" && targetIP == "10.10.100.1" && port == 80 {
				return "tcp connect to 10.10.100.1:80 from ns1 succeeded", nil
			}
			return "tcp connect failed", fmt.Errorf("tcp connect to %s:%d from %s failed", targetIP, port, namespaceName)
		},
		plugins: []*runningPlugin{
			{
				cfg: NSConfig{
					Name:       "ns1",
					VLANID:     100,
					IfName:     "eth0.100",
					IPCIDR:     "10.10.100.2/24",
					MAC:        "02:00:00:00:10:02",
					Gateway:    "10.10.100.1",
					ListenPort: 18080,
					OpenPorts:  []int{19080, 19443},
					AllowICMP:  true,
				},
				rpc: &stubNamespaceService{
					describe: &DescribeResponse{
						Namespace: "ns1",
						HTTPAddr:  ":18080",
						Message:   "plugin ready",
					},
					sftpListHook: func(req SFTPListRequest) (*SFTPListResponse, error) {
						sftpListCalls = append(sftpListCalls, req)
						return &SFTPListResponse{
							Entries: []SFTPEntry{
								{Name: "alpha.txt", Path: "/incoming/alpha.txt", Size: 5, Mode: 0o640},
								{Name: "logs", Path: "/incoming/logs", IsDir: true, Mode: 0o755},
							},
						}, nil
					},
					status: &StatusResponse{
						Namespace:   "ns1",
						Interface:   "eth0.100",
						IPCIDR:      "10.10.100.2/24",
						MAC:         "02:00:00:00:10:02",
						Gateway:     "10.10.100.1",
						OpenPorts:   []int{19080, 19443},
						AllowICMP:   true,
						HTTPAddr:    ":18080",
						HTTPRunning: true,
					},
				},
			},
			{
				cfg: NSConfig{
					Name:       "ns2",
					VLANID:     200,
					IfName:     "eth0.200",
					IPCIDR:     "10.20.0.2/24",
					MAC:        "02:00:00:00:20:02",
					Gateway:    "",
					ListenPort: 18081,
					OpenPorts:  []int{19081},
					AllowICMP:  false,
				},
				rpc: &stubNamespaceService{
					describeErr: errors.New("plugin down"),
					sftpListErr: errors.New("sftp unavailable"),
				},
			},
		},
	}

	t.Run("overview html", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		rec := httptest.NewRecorder()

		service.routes().ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Fatalf("unexpected status code: got %d want %d", rec.Code, http.StatusOK)
		}

		body := rec.Body.String()
		for _, want := range []string{"NetForge Dashboard", "Overview", "Probes", "SFTP Jobs", "Configs", "Namespace Overview", "ns1", "eth0.100", "plugin ready", "19080", "icmp enabled", "10.10.100.1", "02:00:00:00:10:01", "10.10.100.3", "02:00:00:00:10:03", "rx bytes 1024", "tx drop 4", "ns2", "19081", "icmp disabled", "arp unavailable", "statistics unavailable", "plugin down"} {
			if !strings.Contains(body, want) {
				t.Fatalf("dashboard body did not contain %q: %s", want, body)
			}
		}
		for _, unwanted := range []string{"Ping From Namespace", "Add SFTP Sync Job", "Host dashboard:", "Parent NIC:", "Runtime base:"} {
			if strings.Contains(body, unwanted) {
				t.Fatalf("overview page unexpectedly contained %q: %s", unwanted, body)
			}
		}
	})

	t.Run("probes html", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/probes", nil)
		rec := httptest.NewRecorder()

		service.routes().ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Fatalf("unexpected status code: got %d want %d", rec.Code, http.StatusOK)
		}

		body := rec.Body.String()
		for _, want := range []string{"NetForge Dashboard", "Connectivity Probes", "Ping From Namespace", "Test TCP Port", "SFTP File List", "List SFTP Files"} {
			if !strings.Contains(body, want) {
				t.Fatalf("probes body did not contain %q: %s", want, body)
			}
		}
		for _, unwanted := range []string{"rx bytes 1024", "Add SFTP Sync Job", "Host dashboard:", "Parent NIC:", "Runtime base:"} {
			if strings.Contains(body, unwanted) {
				t.Fatalf("probes page unexpectedly contained %q: %s", unwanted, body)
			}
		}
	})

	t.Run("sftp jobs html", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/sftp-jobs", nil)
		rec := httptest.NewRecorder()

		service.routes().ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Fatalf("unexpected status code: got %d want %d", rec.Code, http.StatusOK)
		}

		body := rec.Body.String()
		for _, want := range []string{"NetForge Dashboard", "SFTP Sync Jobs", "Add SFTP Sync Job", "no jobs configured"} {
			if !strings.Contains(body, want) {
				t.Fatalf("jobs body did not contain %q: %s", want, body)
			}
		}
		for _, unwanted := range []string{"Ping From Namespace", "rx bytes 1024", "Host dashboard:", "Parent NIC:", "Runtime base:"} {
			if strings.Contains(body, unwanted) {
				t.Fatalf("jobs page unexpectedly contained %q: %s", unwanted, body)
			}
		}
	})

	t.Run("configs html", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/configs", nil)
		rec := httptest.NewRecorder()

		service.routes().ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Fatalf("unexpected status code: got %d want %d", rec.Code, http.StatusOK)
		}

		body := rec.Body.String()
		for _, want := range []string{
			"NetForge Dashboard",
			"Configs",
			"Host Parameters",
			"Namespace Parameters",
			"HOST_HTTP_ADDR",
			"PARENT_NIC",
			"RUNTIME_BASE",
			"PERSISTENT_BASE",
			"127.0.0.1:8090",
			"eth0",
			"/var/lib/netforge",
			"/data/netforge",
			"name",
			"vlan_id",
			"if_name",
			"ip_cidr",
			"listen_port",
			"open_ports",
			"allow_icmp",
			"ns1",
			"19080, 19443",
			"true",
			"ns2",
			"false",
		} {
			if !strings.Contains(body, want) {
				t.Fatalf("configs body did not contain %q: %s", want, body)
			}
		}
		for _, unwanted := range []string{"Ping From Namespace", "rx bytes 1024", "Add SFTP Sync Job", "Host dashboard:", "Parent NIC:", "Runtime base:"} {
			if strings.Contains(body, unwanted) {
				t.Fatalf("configs page unexpectedly contained %q: %s", unwanted, body)
			}
		}
	})

	t.Run("api", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/namespaces", nil)
		rec := httptest.NewRecorder()

		service.routes().ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Fatalf("unexpected status code: got %d want %d", rec.Code, http.StatusOK)
		}

		var payload hostDashboardData
		if err := json.Unmarshal(rec.Body.Bytes(), &payload); err != nil {
			t.Fatalf("json unmarshal failed: %v", err)
		}
		if payload.ParentNIC != "eth0" {
			t.Fatalf("parent nic mismatch: got %q want %q", payload.ParentNIC, "eth0")
		}
		if payload.PersistentBase != "/data/netforge" {
			t.Fatalf("persistent base mismatch: got %q want %q", payload.PersistentBase, "/data/netforge")
		}
		if len(payload.Namespaces) != 2 {
			t.Fatalf("namespace count mismatch: got %d want %d", len(payload.Namespaces), 2)
		}
		if payload.Namespaces[0].Name != "ns1" || !payload.Namespaces[0].HTTPRunning {
			t.Fatalf("unexpected first namespace payload: %+v", payload.Namespaces[0])
		}
		if !reflect.DeepEqual(payload.Namespaces[0].OpenPorts, []int{19080, 19443}) {
			t.Fatalf("unexpected first namespace open ports: %+v", payload.Namespaces[0])
		}
		if !payload.Namespaces[0].AllowICMP {
			t.Fatalf("expected first namespace allow_icmp=true: %+v", payload.Namespaces[0])
		}
		if len(payload.Namespaces[0].ARPEntries) != 2 {
			t.Fatalf("unexpected first namespace arp entries: %+v", payload.Namespaces[0].ARPEntries)
		}
		if payload.Namespaces[0].ARPEntries[0].IP != "10.10.100.1" || payload.Namespaces[0].ARPEntries[0].MAC != "02:00:00:00:10:01" {
			t.Fatalf("unexpected first arp entry: %+v", payload.Namespaces[0].ARPEntries[0])
		}
		if payload.Namespaces[0].Statistics.RxBytes != 1024 || payload.Namespaces[0].Statistics.TxDropped != 4 {
			t.Fatalf("unexpected first namespace statistics: %+v", payload.Namespaces[0].Statistics)
		}
		if payload.Namespaces[1].AllowICMP {
			t.Fatalf("expected second namespace allow_icmp=false: %+v", payload.Namespaces[1])
		}
		if payload.Namespaces[1].ARPError == "" {
			t.Fatalf("expected second namespace arp error, got %+v", payload.Namespaces[1])
		}
		if payload.Namespaces[1].Error == "" {
			t.Fatalf("expected second namespace error, got %+v", payload.Namespaces[1])
		}
		if payload.Namespaces[1].StatisticsError == "" {
			t.Fatalf("expected second namespace statistics error, got %+v", payload.Namespaces[1])
		}
	})

	t.Run("ping success", func(t *testing.T) {
		pingCalls = nil

		form := url.Values{
			"namespace": {"ns1"},
			"target_ip": {"10.10.100.1"},
		}
		req := httptest.NewRequest(http.MethodPost, "/ping", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		rec := httptest.NewRecorder()

		service.routes().ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Fatalf("unexpected status code: got %d want %d", rec.Code, http.StatusOK)
		}
		if len(pingCalls) != 1 || pingCalls[0] != "ns1->10.10.100.1" {
			t.Fatalf("unexpected ping calls: %+v", pingCalls)
		}

		body := rec.Body.String()
		for _, want := range []string{"Ping succeeded", "ns1", "10.10.100.1", "1 packets transmitted, 1 received"} {
			if !strings.Contains(body, want) {
				t.Fatalf("ping body did not contain %q: %s", want, body)
			}
		}
	})

	t.Run("ping invalid ip", func(t *testing.T) {
		pingCalls = nil

		form := url.Values{
			"namespace": {"ns1"},
			"target_ip": {"not-an-ip"},
		}
		req := httptest.NewRequest(http.MethodPost, "/ping", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		rec := httptest.NewRecorder()

		service.routes().ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Fatalf("unexpected status code: got %d want %d", rec.Code, http.StatusOK)
		}
		if len(pingCalls) != 0 {
			t.Fatalf("expected no ping calls for invalid ip, got %+v", pingCalls)
		}
		if !strings.Contains(rec.Body.String(), "invalid IP address") || !strings.Contains(rec.Body.String(), "not-an-ip") {
			t.Fatalf("expected invalid ip error, got %s", rec.Body.String())
		}
	})

	t.Run("ping unknown namespace", func(t *testing.T) {
		pingCalls = nil

		form := url.Values{
			"namespace": {"ns9"},
			"target_ip": {"10.10.100.1"},
		}
		req := httptest.NewRequest(http.MethodPost, "/ping", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		rec := httptest.NewRecorder()

		service.routes().ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Fatalf("unexpected status code: got %d want %d", rec.Code, http.StatusOK)
		}
		if len(pingCalls) != 0 {
			t.Fatalf("expected no ping calls for unknown namespace, got %+v", pingCalls)
		}
		if !strings.Contains(rec.Body.String(), "unknown namespace") || !strings.Contains(rec.Body.String(), "ns9") {
			t.Fatalf("expected unknown namespace error, got %s", rec.Body.String())
		}
	})

	t.Run("ping failure", func(t *testing.T) {
		pingCalls = nil

		form := url.Values{
			"namespace": {"ns2"},
			"target_ip": {"10.20.0.1"},
		}
		req := httptest.NewRequest(http.MethodPost, "/ping", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		rec := httptest.NewRecorder()

		service.routes().ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Fatalf("unexpected status code: got %d want %d", rec.Code, http.StatusOK)
		}
		if len(pingCalls) != 1 || pingCalls[0] != "ns2->10.20.0.1" {
			t.Fatalf("unexpected ping calls: %+v", pingCalls)
		}
		body := rec.Body.String()
		for _, want := range []string{"Ping failed", "ns2", "10.20.0.1", "PING failed"} {
			if !strings.Contains(body, want) {
				t.Fatalf("ping failure body did not contain %q: %s", want, body)
			}
		}
	})

	t.Run("ping wrong method", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/ping", nil)
		rec := httptest.NewRecorder()

		service.routes().ServeHTTP(rec, req)

		if rec.Code != http.StatusMethodNotAllowed {
			t.Fatalf("unexpected status code: got %d want %d", rec.Code, http.StatusMethodNotAllowed)
		}
	})

	t.Run("tcp success", func(t *testing.T) {
		tcpCheckCalls = nil

		form := url.Values{
			"namespace": {"ns1"},
			"target_ip": {"10.10.100.1"},
			"port":      {"80"},
		}
		req := httptest.NewRequest(http.MethodPost, "/tcp-check", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		rec := httptest.NewRecorder()

		service.routes().ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Fatalf("unexpected status code: got %d want %d", rec.Code, http.StatusOK)
		}
		if len(tcpCheckCalls) != 1 || tcpCheckCalls[0] != "ns1->10.10.100.1:80" {
			t.Fatalf("unexpected tcp check calls: %+v", tcpCheckCalls)
		}

		body := rec.Body.String()
		for _, want := range []string{"TCP port is open", "ns1", "10.10.100.1:80", "tcp connect to 10.10.100.1:80 from ns1 succeeded"} {
			if !strings.Contains(body, want) {
				t.Fatalf("tcp success body did not contain %q: %s", want, body)
			}
		}
	})

	t.Run("tcp invalid port", func(t *testing.T) {
		tcpCheckCalls = nil

		form := url.Values{
			"namespace": {"ns1"},
			"target_ip": {"10.10.100.1"},
			"port":      {"nope"},
		}
		req := httptest.NewRequest(http.MethodPost, "/tcp-check", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		rec := httptest.NewRecorder()

		service.routes().ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Fatalf("unexpected status code: got %d want %d", rec.Code, http.StatusOK)
		}
		if len(tcpCheckCalls) != 0 {
			t.Fatalf("expected no tcp check calls for invalid port, got %+v", tcpCheckCalls)
		}
		if !strings.Contains(rec.Body.String(), "invalid TCP port") || !strings.Contains(rec.Body.String(), "nope") {
			t.Fatalf("expected invalid port error, got %s", rec.Body.String())
		}
	})

	t.Run("tcp unknown namespace", func(t *testing.T) {
		tcpCheckCalls = nil

		form := url.Values{
			"namespace": {"ns9"},
			"target_ip": {"10.10.100.1"},
			"port":      {"80"},
		}
		req := httptest.NewRequest(http.MethodPost, "/tcp-check", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		rec := httptest.NewRecorder()

		service.routes().ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Fatalf("unexpected status code: got %d want %d", rec.Code, http.StatusOK)
		}
		if len(tcpCheckCalls) != 0 {
			t.Fatalf("expected no tcp check calls for unknown namespace, got %+v", tcpCheckCalls)
		}
		if !strings.Contains(rec.Body.String(), "unknown namespace") || !strings.Contains(rec.Body.String(), "ns9") {
			t.Fatalf("expected unknown namespace error, got %s", rec.Body.String())
		}
	})

	t.Run("tcp failure", func(t *testing.T) {
		tcpCheckCalls = nil

		form := url.Values{
			"namespace": {"ns2"},
			"target_ip": {"10.20.0.1"},
			"port":      {"443"},
		}
		req := httptest.NewRequest(http.MethodPost, "/tcp-check", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		rec := httptest.NewRecorder()

		service.routes().ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Fatalf("unexpected status code: got %d want %d", rec.Code, http.StatusOK)
		}
		if len(tcpCheckCalls) != 1 || tcpCheckCalls[0] != "ns2->10.20.0.1:443" {
			t.Fatalf("unexpected tcp check calls: %+v", tcpCheckCalls)
		}
		body := rec.Body.String()
		for _, want := range []string{"TCP port check failed", "ns2", "10.20.0.1:443", "tcp connect failed"} {
			if !strings.Contains(body, want) {
				t.Fatalf("tcp failure body did not contain %q: %s", want, body)
			}
		}
	})

	t.Run("tcp wrong method", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/tcp-check", nil)
		rec := httptest.NewRecorder()

		service.routes().ServeHTTP(rec, req)

		if rec.Code != http.StatusMethodNotAllowed {
			t.Fatalf("unexpected status code: got %d want %d", rec.Code, http.StatusMethodNotAllowed)
		}
	})

	t.Run("sftp success", func(t *testing.T) {
		sftpListCalls = nil

		form := url.Values{
			"namespace":   {"ns1"},
			"server_host": {"10.10.100.1"},
			"port":        {"22"},
			"username":    {"deploy"},
			"password":    {"secret-pass"},
			"directory":   {"/incoming"},
		}
		req := httptest.NewRequest(http.MethodPost, "/sftp-list", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		rec := httptest.NewRecorder()

		service.routes().ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Fatalf("unexpected status code: got %d want %d", rec.Code, http.StatusOK)
		}
		if len(sftpListCalls) != 1 {
			t.Fatalf("unexpected sftp list calls: %+v", sftpListCalls)
		}
		if got := sftpListCalls[0]; got.Connection.Address != "10.10.100.1:22" || got.Connection.Username != "deploy" || got.Connection.Password != "secret-pass" || !got.Connection.InsecureIgnoreHostKey || got.Directory != "/incoming" {
			t.Fatalf("unexpected sftp request: %+v", got)
		}

		body := rec.Body.String()
		for _, want := range []string{"SFTP list succeeded", "ns1", "10.10.100.1:22", "deploy", "/incoming/alpha.txt", "/incoming/logs", "Directory:</strong> <code>/incoming</code>"} {
			if !strings.Contains(body, want) {
				t.Fatalf("sftp success body did not contain %q: %s", want, body)
			}
		}
		if strings.Contains(body, "secret-pass") {
			t.Fatalf("sftp success body leaked password: %s", body)
		}
	})

	t.Run("sftp missing user name", func(t *testing.T) {
		sftpListCalls = nil

		form := url.Values{
			"namespace":   {"ns1"},
			"server_host": {"10.10.100.1"},
			"port":        {"22"},
			"username":    {""},
			"password":    {"secret-pass"},
		}
		req := httptest.NewRequest(http.MethodPost, "/sftp-list", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		rec := httptest.NewRecorder()

		service.routes().ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Fatalf("unexpected status code: got %d want %d", rec.Code, http.StatusOK)
		}
		if len(sftpListCalls) != 0 {
			t.Fatalf("expected no sftp list calls for missing user name, got %+v", sftpListCalls)
		}
		if !strings.Contains(rec.Body.String(), "user name is required") {
			t.Fatalf("expected missing user name error, got %s", rec.Body.String())
		}
	})

	t.Run("sftp failure", func(t *testing.T) {
		sftpListCalls = nil

		form := url.Values{
			"namespace":   {"ns2"},
			"server_host": {"10.20.0.1"},
			"port":        {"22"},
			"username":    {"deploy"},
			"password":    {"secret-pass"},
		}
		req := httptest.NewRequest(http.MethodPost, "/sftp-list", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		rec := httptest.NewRecorder()

		service.routes().ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Fatalf("unexpected status code: got %d want %d", rec.Code, http.StatusOK)
		}
		if len(sftpListCalls) != 0 {
			t.Fatalf("unexpected sftp list calls for ns2: %+v", sftpListCalls)
		}
		body := rec.Body.String()
		for _, want := range []string{"SFTP list failed", "ns2", "10.20.0.1:22", "sftp unavailable"} {
			if !strings.Contains(body, want) {
				t.Fatalf("sftp failure body did not contain %q: %s", want, body)
			}
		}
	})

	t.Run("sftp wrong method", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/sftp-list", nil)
		rec := httptest.NewRecorder()

		service.routes().ServeHTTP(rec, req)

		if rec.Code != http.StatusMethodNotAllowed {
			t.Fatalf("unexpected status code: got %d want %d", rec.Code, http.StatusMethodNotAllowed)
		}
	})
}

func TestHostDashboardSnapshotTimeoutsArePerTaskAndPerNamespace(t *testing.T) {
	originalTimeout := dashboardSnapshotTaskTimeout
	dashboardSnapshotTaskTimeout = 25 * time.Millisecond
	defer func() {
		dashboardSnapshotTaskTimeout = originalTimeout
	}()

	blocker := make(chan struct{})
	defer close(blocker)

	service := &hostDashboardService{
		addr:           "127.0.0.1:8090",
		parentNIC:      "eth0",
		runtimeBase:    "/var/lib/netforge",
		persistentBase: "/data/netforge",
		statsLookup: func(namespaceName, ifName string) (hostNICStatisticsView, error) {
			if namespaceName == "stuck" {
				<-blocker
			}
			return hostNICStatisticsView{RxBytes: 77}, nil
		},
		arpLookup: func(namespaceName, ifName string) ([]hostARPEntryView, error) {
			if namespaceName == "stuck" {
				<-blocker
			}
			return []hostARPEntryView{{IP: "10.0.0.1", MAC: "02:00:00:00:00:01"}}, nil
		},
		plugins: []*runningPlugin{
			{
				cfg: NSConfig{
					Name:       "stuck",
					VLANID:     100,
					IfName:     "eth0.100",
					IPCIDR:     "10.10.0.2/24",
					MAC:        "02:00:00:00:10:02",
					Gateway:    "10.10.0.1",
					ListenPort: 18080,
					OpenPorts:  []int{18080},
					AllowICMP:  true,
				},
				rpc: &delayedNamespaceService{
					describeWait: blocker,
					status: &StatusResponse{
						Namespace:   "stuck",
						Interface:   "eth0.100",
						IPCIDR:      "10.10.0.2/24",
						MAC:         "02:00:00:00:10:02",
						Gateway:     "10.10.0.1",
						OpenPorts:   []int{18080},
						AllowICMP:   true,
						HTTPAddr:    ":18080",
						HTTPRunning: true,
					},
				},
			},
			{
				cfg: NSConfig{
					Name:       "healthy",
					VLANID:     200,
					IfName:     "eth0.200",
					IPCIDR:     "10.20.0.2/24",
					MAC:        "02:00:00:00:20:02",
					Gateway:    "",
					ListenPort: 18081,
					OpenPorts:  []int{18081},
				},
				rpc: &stubNamespaceService{
					describe: &DescribeResponse{
						Namespace: "healthy",
						HTTPAddr:  ":18081",
						Message:   "plugin ready",
					},
					status: &StatusResponse{
						Namespace:   "healthy",
						Interface:   "eth0.200",
						IPCIDR:      "10.20.0.2/24",
						MAC:         "02:00:00:00:20:02",
						OpenPorts:   []int{18081},
						HTTPAddr:    ":18081",
						HTTPRunning: true,
					},
				},
			},
		},
	}

	done := make(chan hostDashboardData, 1)
	start := time.Now()
	go func() {
		done <- service.snapshot()
	}()

	var snapshot hostDashboardData
	select {
	case snapshot = <-done:
	case <-time.After(250 * time.Millisecond):
		t.Fatal("snapshot blocked on a bad namespace")
	}
	if elapsed := time.Since(start); elapsed > 200*time.Millisecond {
		t.Fatalf("snapshot took too long: %s", elapsed)
	}

	if len(snapshot.Namespaces) != 2 {
		t.Fatalf("unexpected namespace count: %+v", snapshot.Namespaces)
	}
	if snapshot.Namespaces[0].Name != "stuck" || snapshot.Namespaces[1].Name != "healthy" {
		t.Fatalf("snapshot order changed: %+v", snapshot.Namespaces)
	}

	stuck := snapshot.Namespaces[0]
	if !strings.Contains(stuck.StatisticsError, "timed out") {
		t.Fatalf("expected statistics timeout, got %+v", stuck)
	}
	if !strings.Contains(stuck.ARPError, "timed out") {
		t.Fatalf("expected arp timeout, got %+v", stuck)
	}
	if !strings.Contains(stuck.Error, "describe failed") || !strings.Contains(stuck.Error, "timed out") {
		t.Fatalf("expected describe timeout error, got %+v", stuck)
	}
	if !stuck.HTTPRunning || stuck.PluginHTTPAddr != ":18080" {
		t.Fatalf("expected status partial result for stuck namespace, got %+v", stuck)
	}

	healthy := snapshot.Namespaces[1]
	if healthy.Error != "" || healthy.StatisticsError != "" || healthy.ARPError != "" {
		t.Fatalf("healthy namespace should not inherit another namespace stall: %+v", healthy)
	}
	if healthy.Statistics.RxBytes != 77 {
		t.Fatalf("unexpected healthy namespace statistics: %+v", healthy)
	}
	if healthy.PluginHTTPAddr != ":18081" || !healthy.HTTPRunning {
		t.Fatalf("unexpected healthy namespace status: %+v", healthy)
	}
}

func requireIntegration(t *testing.T) {
	t.Helper()

	if runtime.GOOS != "linux" {
		t.Fatal("linux only")
	}
	if os.Geteuid() != 0 {
		t.Skip("integration tests require root privileges")
	}
}

func cleanupHostLink(name string) {
	link, err := netlink.LinkByName(name)
	if err == nil {
		_ = netlink.LinkDel(link)
	}
}

func deleteLinkInNamespace(ns netns.NsHandle, linkName string) error {
	handle, err := netlink.NewHandleAt(ns)
	if err != nil {
		return err
	}
	defer handle.Delete()

	link, err := handle.LinkByName(linkName)
	if err != nil {
		return nil
	}
	return handle.LinkDel(link)
}

func buildPackageBinary(t *testing.T) string {
	t.Helper()

	out := filepath.Join(t.TempDir(), "ns-demo-bin")
	cmd := exec.Command("go", "build", "-buildvcs=false", "-o", out, ".")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Env = append(os.Environ(), "CGO_ENABLED=0")
	if err := cmd.Run(); err != nil {
		t.Fatalf("go build failed: %v", err)
	}
	return out
}

func uniqueNamespaceToken() string {
	return fmt.Sprintf("%02x%04x", os.Getpid()&0xff, uint64(time.Now().UnixNano())&0xffff)
}

func freeLocalTCPPort(t *testing.T) int {
	t.Helper()

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve local tcp port failed: %v", err)
	}
	defer listener.Close()

	addr, ok := listener.Addr().(*net.TCPAddr)
	if !ok {
		t.Fatalf("unexpected listener addr type: %T", listener.Addr())
	}
	return addr.Port
}

func httpGetInNamespace(namespaceName, rawURL string) (string, int, error) {
	req, err := http.NewRequest(http.MethodGet, rawURL, nil)
	if err != nil {
		return "", 0, err
	}

	addr, err := namespaceHTTPAddress(req.URL)
	if err != nil {
		return "", 0, err
	}

	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return "", 0, err
	}
	hostHeader := req.URL.Host
	script := fmt.Sprintf(
		"exec 3<>/dev/tcp/%s/%s; printf 'GET %s HTTP/1.1\\r\\nHost: %s\\r\\nConnection: close\\r\\n\\r\\n' >&3; cat <&3",
		host,
		port,
		req.URL.RequestURI(),
		hostHeader,
	)

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, "bash", "-lc", script)
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := startCmdInNamedNamespace(cmd, namespaceName); err != nil {
		return "", 0, err
	}
	if err := cmd.Wait(); err != nil {
		if stderr.Len() > 0 {
			return "", 0, fmt.Errorf("%w: %s", err, strings.TrimSpace(stderr.String()))
		}
		return "", 0, err
	}

	resp, err := http.ReadResponse(bufio.NewReader(bytes.NewReader(stdout.Bytes())), req)
	if err != nil {
		return "", 0, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", 0, err
	}
	return string(body), resp.StatusCode, nil
}

func namespaceHTTPAddress(u *url.URL) (string, error) {
	if u == nil {
		return "", os.ErrInvalid
	}
	if u.Host == "" {
		return "", &url.Error{Op: "parse", URL: u.String(), Err: os.ErrInvalid}
	}
	if _, _, err := net.SplitHostPort(u.Host); err == nil {
		return u.Host, nil
	}

	switch u.Scheme {
	case "http":
		return net.JoinHostPort(u.Host, "80"), nil
	case "https":
		return net.JoinHostPort(u.Host, "443"), nil
	default:
		return "", &url.Error{Op: "parse", URL: u.String(), Err: os.ErrInvalid}
	}
}

func routeIsDefaultV4(route netlink.Route) bool {
	if route.Dst == nil {
		return true
	}
	if route.Dst.IP == nil || route.Dst.IP.To4() == nil {
		return false
	}
	ones, bits := route.Dst.Mask.Size()
	return bits == 32 && ones == 0
}

func nftRuleAcceptsTCPPort(rule *nftables.Rule, port int) bool {
	wantPort := binaryutil.BigEndian.PutUint16(uint16(port))
	sawTCP := false
	sawPort := false
	sawAccept := false

	for _, expression := range rule.Exprs {
		switch exprValue := expression.(type) {
		case *expr.Cmp:
			if bytes.Equal(exprValue.Data, []byte{unix.IPPROTO_TCP}) {
				sawTCP = true
			}
			if bytes.Equal(exprValue.Data, wantPort) {
				sawPort = true
			}
		case *expr.Verdict:
			if exprValue.Kind == expr.VerdictAccept {
				sawAccept = true
			}
		}
	}

	return sawTCP && sawPort && sawAccept
}

func nftRuleAcceptsProtocol(rule *nftables.Rule, proto byte) bool {
	sawProto := false
	sawAccept := false

	for _, expression := range rule.Exprs {
		switch exprValue := expression.(type) {
		case *expr.Cmp:
			if bytes.Equal(exprValue.Data, []byte{proto}) {
				sawProto = true
			}
		case *expr.Verdict:
			if exprValue.Kind == expr.VerdictAccept {
				sawAccept = true
			}
		}
	}

	return sawProto && sawAccept
}

func nftRuleAcceptsLoopback(rule *nftables.Rule) bool {
	sawLoopback := false
	sawAccept := false

	for _, expression := range rule.Exprs {
		switch exprValue := expression.(type) {
		case *expr.Cmp:
			if bytes.Equal(exprValue.Data, nftablesInterfaceName("lo")) {
				sawLoopback = true
			}
		case *expr.Verdict:
			if exprValue.Kind == expr.VerdictAccept {
				sawAccept = true
			}
		}
	}

	return sawLoopback && sawAccept
}

func namespaceFirewallAllowsTCPPort(ns netns.NsHandle, port int) (bool, error) {
	conn, err := nftables.New(nftables.WithNetNSFd(int(ns)))
	if err != nil {
		return false, err
	}

	table, err := lookupNFTablesTable(conn, nftables.TableFamilyINet, namespaceFirewallTableName)
	if err != nil {
		return false, err
	}
	if table == nil {
		return false, nil
	}

	chain, err := conn.ListChain(table, namespaceFirewallInputName)
	if err != nil {
		return false, err
	}
	if chain.Policy == nil || *chain.Policy != nftables.ChainPolicyDrop {
		return false, fmt.Errorf("unexpected chain policy: %+v", chain.Policy)
	}

	rules, err := conn.GetRules(table, chain)
	if err != nil {
		return false, err
	}
	for _, rule := range rules {
		if nftRuleAcceptsTCPPort(rule, port) {
			return true, nil
		}
	}
	return false, nil
}

func namespaceFirewallAllowsProtocol(ns netns.NsHandle, proto byte) (bool, error) {
	conn, err := nftables.New(nftables.WithNetNSFd(int(ns)))
	if err != nil {
		return false, err
	}

	table, err := lookupNFTablesTable(conn, nftables.TableFamilyINet, namespaceFirewallTableName)
	if err != nil {
		return false, err
	}
	if table == nil {
		return false, nil
	}

	chain, err := conn.ListChain(table, namespaceFirewallInputName)
	if err != nil {
		return false, err
	}

	rules, err := conn.GetRules(table, chain)
	if err != nil {
		return false, err
	}
	for _, rule := range rules {
		if nftRuleAcceptsProtocol(rule, proto) {
			return true, nil
		}
	}
	return false, nil
}

func namespaceFirewallAllowsLoopback(ns netns.NsHandle) (bool, error) {
	conn, err := nftables.New(nftables.WithNetNSFd(int(ns)))
	if err != nil {
		return false, err
	}

	table, err := lookupNFTablesTable(conn, nftables.TableFamilyINet, namespaceFirewallTableName)
	if err != nil {
		return false, err
	}
	if table == nil {
		return false, nil
	}

	chain, err := conn.ListChain(table, namespaceFirewallInputName)
	if err != nil {
		return false, err
	}

	rules, err := conn.GetRules(table, chain)
	if err != nil {
		return false, err
	}
	for _, rule := range rules {
		if nftRuleAcceptsLoopback(rule) {
			return true, nil
		}
	}
	return false, nil
}

func waitForHTTP(t *testing.T, fn func() (string, int, error)) {
	t.Helper()

	deadline := time.Now().Add(10 * time.Second)
	var lastErr error
	for time.Now().Before(deadline) {
		_, _, err := fn()
		if err == nil {
			return
		}
		lastErr = err
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("http server did not become ready: %v", lastErr)
}

func TestSetupNamespaceNetworkWithDummyParent(t *testing.T) {
	requireIntegration(t)

	token := uniqueNamespaceToken()
	parentName := "d" + token
	nsName := "tns" + token
	cfg := NSConfig{
		Name:       nsName,
		VLANID:     100,
		IfName:     parentName + ".100",
		IPCIDR:     "10.10.100.2/24",
		MAC:        "02:00:00:00:10:02",
		Gateway:    "10.10.100.1",
		ListenPort: 18080,
		OpenPorts:  []int{19080, 19443},
		AllowICMP:  true,
	}

	cleanupHostLink(cfg.IfName)
	cleanupHostLink(parentName)
	_ = netns.DeleteNamed(nsName)

	dummy := &netlink.Dummy{LinkAttrs: netlink.NewLinkAttrs()}
	dummy.LinkAttrs.Name = parentName
	if err := netlink.LinkAdd(dummy); err != nil {
		t.Fatalf("create dummy parent failed: %v", err)
	}
	parent, err := netlink.LinkByName(parentName)
	if err != nil {
		t.Fatalf("lookup dummy parent failed: %v", err)
	}
	if err := netlink.LinkSetUp(parent); err != nil {
		t.Fatalf("bring dummy parent up failed: %v", err)
	}

	ns, err := setupNamespaceNetwork(parentName, cfg)
	if err != nil {
		t.Fatalf("setupNamespaceNetwork failed: %v", err)
	}

	t.Cleanup(func() {
		_ = deleteLinkInNamespace(ns, cfg.IfName)
		_ = ns.Close()
		_ = netns.DeleteNamed(nsName)
		cleanupHostLink(parentName)
		cleanupHostLink(cfg.IfName)
	})

	handle, err := netlink.NewHandleAt(ns)
	if err != nil {
		t.Fatalf("NewHandleAt failed: %v", err)
	}
	defer handle.Delete()

	link, err := handle.LinkByName(cfg.IfName)
	if err != nil {
		t.Fatalf("lookup link in namespace failed: %v", err)
	}
	if got := link.Attrs().HardwareAddr.String(); got != cfg.MAC {
		t.Fatalf("mac mismatch: got %s want %s", got, cfg.MAC)
	}

	addrs, err := handle.AddrList(link, netlink.FAMILY_V4)
	if err != nil {
		t.Fatalf("AddrList failed: %v", err)
	}
	foundAddr := false
	for _, addr := range addrs {
		if addr.IPNet != nil && addr.IPNet.String() == cfg.IPCIDR {
			foundAddr = true
			break
		}
	}
	if !foundAddr {
		t.Fatalf("did not find address %s in namespace", cfg.IPCIDR)
	}

	stats, err := lookupNamespaceNICStatistics(nsName, cfg.IfName)
	if err != nil {
		t.Fatalf("lookupNamespaceNICStatistics failed: %v", err)
	}
	if stats.RxBytes > 0 && stats.RxPackets == 0 {
		t.Fatalf("unexpected statistics relationship: %+v", stats)
	}

	routes, err := handle.RouteList(link, netlink.FAMILY_V4)
	if err != nil {
		t.Fatalf("RouteList failed: %v", err)
	}
	foundDefault := false
	for _, route := range routes {
		if routeIsDefaultV4(route) && route.Gw != nil && route.Gw.String() == cfg.Gateway {
			foundDefault = true
			break
		}
	}
	if !foundDefault {
		t.Fatalf("did not find default route via %s", cfg.Gateway)
	}

	neighbor1MAC, err := net.ParseMAC("02:00:00:00:10:01")
	if err != nil {
		t.Fatalf("ParseMAC neighbor1 failed: %v", err)
	}
	neighbor2MAC, err := net.ParseMAC("02:00:00:00:10:03")
	if err != nil {
		t.Fatalf("ParseMAC neighbor2 failed: %v", err)
	}
	if err := handle.NeighSet(&netlink.Neigh{
		LinkIndex:    link.Attrs().Index,
		IP:           net.ParseIP("10.10.100.3"),
		HardwareAddr: neighbor2MAC,
		State:        netlink.NUD_PERMANENT,
	}); err != nil {
		t.Fatalf("NeighSet neighbor2 failed: %v", err)
	}
	if err := handle.NeighSet(&netlink.Neigh{
		LinkIndex:    link.Attrs().Index,
		IP:           net.ParseIP("10.10.100.1"),
		HardwareAddr: neighbor1MAC,
		State:        netlink.NUD_PERMANENT,
	}); err != nil {
		t.Fatalf("NeighSet neighbor1 failed: %v", err)
	}

	arpEntries, err := lookupNamespaceARPTable(nsName, cfg.IfName)
	if err != nil {
		t.Fatalf("lookupNamespaceARPTable failed: %v", err)
	}
	if len(arpEntries) != 2 {
		t.Fatalf("unexpected arp entry count: %+v", arpEntries)
	}
	if arpEntries[0].IP != "10.10.100.1" || arpEntries[0].MAC != "02:00:00:00:10:01" {
		t.Fatalf("unexpected first arp entry: %+v", arpEntries[0])
	}
	if arpEntries[1].IP != "10.10.100.3" || arpEntries[1].MAC != "02:00:00:00:10:03" {
		t.Fatalf("unexpected second arp entry: %+v", arpEntries[1])
	}

	for _, port := range cfg.OpenPorts {
		allowsPort, err := namespaceFirewallAllowsTCPPort(ns, port)
		if err != nil {
			t.Fatalf("namespace firewall lookup failed for %d: %v", port, err)
		}
		if !allowsPort {
			t.Fatalf("namespace firewall did not allow tcp port %d", port)
		}
	}

	allowsICMP, err := namespaceFirewallAllowsProtocol(ns, unix.IPPROTO_ICMP)
	if err != nil {
		t.Fatalf("namespace firewall icmp lookup failed: %v", err)
	}
	if !allowsICMP {
		t.Fatal("namespace firewall did not allow icmp")
	}

	allowsICMPv6, err := namespaceFirewallAllowsProtocol(ns, unix.IPPROTO_ICMPV6)
	if err != nil {
		t.Fatalf("namespace firewall icmpv6 lookup failed: %v", err)
	}
	if !allowsICMPv6 {
		t.Fatal("namespace firewall did not allow icmpv6")
	}

	allowsLoopback, err := namespaceFirewallAllowsLoopback(ns)
	if err != nil {
		t.Fatalf("namespace firewall loopback lookup failed: %v", err)
	}
	if allowsLoopback {
		t.Fatal("namespace firewall unexpectedly bypassed loopback traffic")
	}

	firewallState := firewallStateForNamespace(t, ns)
	if firewallState.forwardChain == nil || firewallState.forwardChain.Policy == nil || *firewallState.forwardChain.Policy != nftables.ChainPolicyDrop {
		t.Fatalf("namespace firewall forward chain was not drop-policy: %+v", firewallState.forwardChain)
	}
}

func TestExternalPluginInNamespaceEndToEnd(t *testing.T) {
	requireIntegration(t)

	token := uniqueNamespaceToken()
	parentName := "d" + token
	nsName := "tns" + token
	listenPort := freeLocalTCPPort(t)
	cfg := NSConfig{
		Name:       nsName,
		VLANID:     200,
		IfName:     parentName + ".200",
		IPCIDR:     "10.20.0.2/24",
		MAC:        "02:00:00:00:20:02",
		Gateway:    "",
		ListenPort: listenPort,
		OpenPorts:  []int{listenPort},
	}

	cleanupHostLink(cfg.IfName)
	cleanupHostLink(parentName)
	_ = netns.DeleteNamed(nsName)

	dummy := &netlink.Dummy{LinkAttrs: netlink.NewLinkAttrs()}
	dummy.LinkAttrs.Name = parentName
	if err := netlink.LinkAdd(dummy); err != nil {
		t.Fatalf("create dummy parent failed: %v", err)
	}
	parent, err := netlink.LinkByName(parentName)
	if err != nil {
		t.Fatalf("lookup dummy parent failed: %v", err)
	}
	if err := netlink.LinkSetUp(parent); err != nil {
		t.Fatalf("bring dummy parent up failed: %v", err)
	}

	ns, err := setupNamespaceNetwork(parentName, cfg)
	if err != nil {
		t.Fatalf("setupNamespaceNetwork failed: %v", err)
	}

	bin := buildPackageBinary(t)
	proc, err := startNamespacePlugin(bin, t.TempDir(), t.TempDir(), cfg)
	if err != nil {
		t.Fatalf("startNamespacePlugin failed: %v", err)
	}

	t.Cleanup(func() {
		proc.Stop()
		_ = deleteLinkInNamespace(ns, cfg.IfName)
		_ = ns.Close()
		_ = netns.DeleteNamed(nsName)
		cleanupHostLink(parentName)
		cleanupHostLink(cfg.IfName)
	})

	desc, err := proc.rpc.Describe()
	if err != nil {
		t.Fatalf("Describe failed: %v", err)
	}
	if desc.Namespace != nsName {
		t.Fatalf("describe namespace mismatch: got %q want %q", desc.Namespace, nsName)
	}

	status, err := proc.rpc.Status()
	if err != nil {
		t.Fatalf("Status failed: %v", err)
	}
	if !status.HTTPRunning {
		t.Fatal("expected HTTPRunning=true")
	}

	assertPluginSandboxed(t, proc)

	waitForHTTP(t, func() (string, int, error) {
		return httpGetInNamespace(nsName, fmt.Sprintf("http://127.0.0.1:%d/healthz", cfg.ListenPort))
	})

	checkTCPOutput, err := proc.rpc.CheckTCPPort("127.0.0.1", cfg.ListenPort)
	if err != nil {
		t.Fatalf("CheckTCPPort failed: %v", err)
	}
	if !strings.Contains(checkTCPOutput, fmt.Sprintf("tcp connect to 127.0.0.1:%d from %s succeeded", cfg.ListenPort, nsName)) {
		t.Fatalf("unexpected CheckTCPPort output: %q", checkTCPOutput)
	}

	body, code, err := httpGetInNamespace(nsName, fmt.Sprintf("http://127.0.0.1:%d/", cfg.ListenPort))
	if err != nil {
		t.Fatalf("namespace GET / failed: %v", err)
	}
	if code != http.StatusOK {
		t.Fatalf("unexpected status code: got %d", code)
	}
	if !strings.Contains(body, "namespace="+nsName) {
		t.Fatalf("unexpected body: %s", body)
	}

	if err := proc.rpc.StopHTTP(); err != nil {
		t.Fatalf("StopHTTP via rpc failed: %v", err)
	}

	status, err = proc.rpc.Status()
	if err != nil {
		t.Fatalf("Status after stop failed: %v", err)
	}
	if status.HTTPRunning {
		t.Fatal("expected HTTPRunning=false after rpc stop")
	}
}
