//go:build linux

package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	goping "github.com/go-ping/ping"
	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netns"
)

type hostNamespaceView struct {
	Name            string                `json:"name"`
	VLANID          int                   `json:"vlan_id"`
	Interface       string                `json:"interface"`
	IPCIDR          string                `json:"ip_cidr"`
	MAC             string                `json:"mac"`
	Gateway         string                `json:"gateway"`
	ListenPort      int                   `json:"listen_port"`
	OpenPorts       []int                 `json:"open_ports"`
	AllowICMP       bool                  `json:"allow_icmp"`
	PluginHTTPAddr  string                `json:"plugin_http_addr"`
	HTTPRunning     bool                  `json:"http_running"`
	Message         string                `json:"message"`
	Error           string                `json:"error,omitempty"`
	Statistics      hostNICStatisticsView `json:"statistics"`
	StatisticsError string                `json:"statistics_error,omitempty"`
	ARPEntries      []hostARPEntryView    `json:"arp_entries,omitempty"`
	ARPError        string                `json:"arp_error,omitempty"`
}

type hostDashboardData struct {
	HostHTTPAddr          string                  `json:"host_http_addr"`
	ParentNIC             string                  `json:"parent_nic"`
	RuntimeBase           string                  `json:"runtime_base"`
	PersistentBase        string                  `json:"persistent_base"`
	CurrentPage           string                  `json:"-"`
	PageTitle             string                  `json:"-"`
	PageDescription       string                  `json:"-"`
	Namespaces            []hostNamespaceView     `json:"namespaces"`
	Jobs                  []hostSFTPSyncJobView   `json:"jobs,omitempty"`
	JobsError             string                  `json:"jobs_error,omitempty"`
	SFTPJobForm           hostSFTPSyncJobFormData `json:"sftp_job_form,omitempty"`
	SFTPJobMessage        string                  `json:"sftp_job_message,omitempty"`
	SFTPJobError          string                  `json:"sftp_job_error,omitempty"`
	SelectedPingNamespace string                  `json:"selected_ping_namespace,omitempty"`
	PingTargetIP          string                  `json:"ping_target_ip,omitempty"`
	PingResult            *hostPingResultView     `json:"ping_result,omitempty"`
	SelectedTCPNamespace  string                  `json:"selected_tcp_namespace,omitempty"`
	TCPTargetIP           string                  `json:"tcp_target_ip,omitempty"`
	TCPTargetPort         string                  `json:"tcp_target_port,omitempty"`
	TCPCheckResult        *hostTCPResultView      `json:"tcp_check_result,omitempty"`
	SelectedSFTPNamespace string                  `json:"selected_sftp_namespace,omitempty"`
	SFTPServerHost        string                  `json:"sftp_server_host,omitempty"`
	SFTPServerPort        string                  `json:"sftp_server_port,omitempty"`
	SFTPUsername          string                  `json:"sftp_username,omitempty"`
	SFTPDirectory         string                  `json:"sftp_directory,omitempty"`
	SFTPListResult        *hostSFTPResultView     `json:"sftp_list_result,omitempty"`
}

type hostNICStatisticsView struct {
	RxBytes   uint64 `json:"rx_bytes"`
	TxBytes   uint64 `json:"tx_bytes"`
	RxPackets uint64 `json:"rx_packets"`
	TxPackets uint64 `json:"tx_packets"`
	RxErrors  uint64 `json:"rx_errors"`
	TxErrors  uint64 `json:"tx_errors"`
	RxDropped uint64 `json:"rx_dropped"`
	TxDropped uint64 `json:"tx_dropped"`
}

type hostARPEntryView struct {
	IP  string `json:"ip"`
	MAC string `json:"mac"`
}

type hostPingResultView struct {
	Namespace string `json:"namespace"`
	TargetIP  string `json:"target_ip"`
	Success   bool   `json:"success"`
	Output    string `json:"output,omitempty"`
	Error     string `json:"error,omitempty"`
}

type hostTCPResultView struct {
	Namespace string `json:"namespace"`
	TargetIP  string `json:"target_ip"`
	Port      int    `json:"port"`
	Success   bool   `json:"success"`
	Output    string `json:"output,omitempty"`
	Error     string `json:"error,omitempty"`
}

type hostSFTPResultView struct {
	Namespace string      `json:"namespace"`
	Server    string      `json:"server"`
	Port      int         `json:"port"`
	Username  string      `json:"username"`
	Directory string      `json:"directory"`
	Success   bool        `json:"success"`
	Entries   []SFTPEntry `json:"entries,omitempty"`
	Error     string      `json:"error,omitempty"`
}

type hostDashboardService struct {
	addr           string
	parentNIC      string
	runtimeBase    string
	persistentBase string
	plugins        []*runningPlugin
	jobManager     *sftpSyncJobManager
	statsLookup    func(namespaceName, ifName string) (hostNICStatisticsView, error)
	arpLookup      func(namespaceName, ifName string) ([]hostARPEntryView, error)
	pingFunc       func(namespaceName, targetIP string) (string, error)
	tcpCheckFunc   func(namespaceName, targetIP string, port int) (string, error)
}

var dashboardSnapshotTaskTimeout = 750 * time.Millisecond

var (
	getNamedNamespaceHandle = netns.GetFromName
	getCurrentNamespace     = netns.Get
	setCurrentNamespace     = netns.Set
	runInNamedNamespace     = withNamedNamespace
	newNamespacePinger      = func(addr string) namespacePinger {
		return &goNamespacePinger{Pinger: goping.New(addr)}
	}
)

type dashboardTaskResult[T any] struct {
	value T
	err   error
}

type namespacePingPacket struct {
	NBytes int
	IPAddr string
	Seq    int
	Rtt    time.Duration
}

type namespacePingStats struct {
	PacketsSent int
	PacketsRecv int
	PacketLoss  float64
	Addr        string
	IPAddr      string
	MinRtt      time.Duration
	AvgRtt      time.Duration
	MaxRtt      time.Duration
	StdDevRtt   time.Duration
}

type namespacePinger interface {
	SetNetwork(string)
	SetPrivileged(bool)
	SetCount(int)
	SetInterval(time.Duration)
	SetTimeout(time.Duration)
	SetOnRecv(func(namespacePingPacket))
	Run() error
	Statistics() namespacePingStats
}

type goNamespacePinger struct {
	*goping.Pinger
}

func (p *goNamespacePinger) SetCount(count int) {
	p.Pinger.Count = count
}

func (p *goNamespacePinger) SetInterval(interval time.Duration) {
	p.Pinger.Interval = interval
}

func (p *goNamespacePinger) SetTimeout(timeout time.Duration) {
	p.Pinger.Timeout = timeout
}

func (p *goNamespacePinger) SetOnRecv(handler func(namespacePingPacket)) {
	p.Pinger.OnRecv = func(pkt *goping.Packet) {
		ipAddr := ""
		if pkt.IPAddr != nil {
			ipAddr = pkt.IPAddr.String()
		}
		handler(namespacePingPacket{
			NBytes: pkt.Nbytes,
			IPAddr: ipAddr,
			Seq:    pkt.Seq,
			Rtt:    pkt.Rtt,
		})
	}
}

func (p *goNamespacePinger) Statistics() namespacePingStats {
	stats := p.Pinger.Statistics()
	ipAddr := ""
	if stats.IPAddr != nil {
		ipAddr = stats.IPAddr.String()
	}
	return namespacePingStats{
		PacketsSent: stats.PacketsSent,
		PacketsRecv: stats.PacketsRecv,
		PacketLoss:  stats.PacketLoss,
		Addr:        stats.Addr,
		IPAddr:      ipAddr,
		MinRtt:      stats.MinRtt,
		AvgRtt:      stats.AvgRtt,
		MaxRtt:      stats.MaxRtt,
		StdDevRtt:   stats.StdDevRtt,
	}
}

func startDashboardTask[T any](ctx context.Context, name string, fn func() (T, error)) <-chan dashboardTaskResult[T] {
	resultCh := make(chan dashboardTaskResult[T], 1)
	timeout := dashboardSnapshotTaskTimeout
	go func() {
		doneCh := make(chan dashboardTaskResult[T], 1)
		go func() {
			value, err := fn()
			doneCh <- dashboardTaskResult[T]{value: value, err: err}
		}()

		timer := time.NewTimer(timeout)
		defer timer.Stop()

		select {
		case result := <-doneCh:
			resultCh <- result
		case <-timer.C:
			resultCh <- dashboardTaskResult[T]{err: fmt.Errorf("%s timed out after %s", name, timeout)}
		case <-ctx.Done():
			resultCh <- dashboardTaskResult[T]{err: fmt.Errorf("%s canceled: %w", name, ctx.Err())}
		}
	}()
	return resultCh
}

func appendDashboardError(existing *string, message string) {
	if message == "" {
		return
	}
	if *existing == "" {
		*existing = message
		return
	}
	*existing += "; " + message
}

var hostDashboardTemplate = newHostDashboardTemplate()

func (s *hostDashboardService) snapshot() hostDashboardData {
	return s.snapshotWithContext(context.Background())
}

func (s *hostDashboardService) snapshotWithContext(ctx context.Context) hostDashboardData {
	namespaces := make([]hostNamespaceView, len(s.plugins))
	statsLookup := s.statsLookup
	if statsLookup == nil {
		statsLookup = lookupNamespaceNICStatistics
	}
	arpLookup := s.arpLookup
	if arpLookup == nil {
		arpLookup = lookupNamespaceARPTable
	}

	var wg sync.WaitGroup
	for i, plugin := range s.plugins {
		i := i
		plugin := plugin
		wg.Add(1)
		go func() {
			defer wg.Done()

			view := hostNamespaceView{
				Name:       plugin.cfg.Name,
				VLANID:     plugin.cfg.VLANID,
				Interface:  plugin.cfg.IfName,
				IPCIDR:     plugin.cfg.IPCIDR,
				MAC:        plugin.cfg.MAC,
				Gateway:    plugin.cfg.Gateway,
				ListenPort: plugin.cfg.ListenPort,
				OpenPorts:  cloneOpenPorts(plugin.cfg.OpenPorts),
				AllowICMP:  plugin.cfg.AllowICMP,
			}

			statsTask := startDashboardTask(ctx, fmt.Sprintf("statistics lookup for namespace %q", plugin.cfg.Name), func() (hostNICStatisticsView, error) {
				return statsLookup(plugin.cfg.Name, plugin.cfg.IfName)
			})
			arpTask := startDashboardTask(ctx, fmt.Sprintf("arp lookup for namespace %q", plugin.cfg.Name), func() ([]hostARPEntryView, error) {
				return arpLookup(plugin.cfg.Name, plugin.cfg.IfName)
			})

			var describeTask <-chan dashboardTaskResult[*DescribeResponse]
			var statusTask <-chan dashboardTaskResult[*StatusResponse]
			if plugin.rpc == nil {
				view.Error = "plugin rpc unavailable"
			} else {
				describeTask = startDashboardTask(ctx, fmt.Sprintf("describe rpc for namespace %q", plugin.cfg.Name), plugin.rpc.Describe)
				statusTask = startDashboardTask(ctx, fmt.Sprintf("status rpc for namespace %q", plugin.cfg.Name), plugin.rpc.Status)
			}

			stats := <-statsTask
			if stats.err != nil {
				view.StatisticsError = stats.err.Error()
			} else {
				view.Statistics = stats.value
			}

			arpEntries := <-arpTask
			if arpEntries.err != nil {
				view.ARPError = arpEntries.err.Error()
			} else {
				view.ARPEntries = arpEntries.value
			}

			if describeTask != nil {
				describe := <-describeTask
				if describe.err != nil {
					appendDashboardError(&view.Error, fmt.Sprintf("describe failed: %v", describe.err))
				} else {
					view.Message = describe.value.Message
					if describe.value.HTTPAddr != "" {
						view.PluginHTTPAddr = describe.value.HTTPAddr
					}
				}
			}

			if statusTask != nil {
				status := <-statusTask
				if status.err != nil {
					appendDashboardError(&view.Error, fmt.Sprintf("status failed: %v", status.err))
				} else {
					if status.value.Interface != "" {
						view.Interface = status.value.Interface
					}
					if status.value.IPCIDR != "" {
						view.IPCIDR = status.value.IPCIDR
					}
					if status.value.MAC != "" {
						view.MAC = status.value.MAC
					}
					if status.value.Gateway != "" {
						view.Gateway = status.value.Gateway
					}
					if status.value.OpenPorts != nil {
						view.OpenPorts = cloneOpenPorts(status.value.OpenPorts)
					}
					view.AllowICMP = status.value.AllowICMP
					if status.value.HTTPAddr != "" {
						view.PluginHTTPAddr = status.value.HTTPAddr
					}
					view.HTTPRunning = status.value.HTTPRunning
				}
			}

			namespaces[i] = view
		}()
	}
	wg.Wait()

	data := hostDashboardData{
		HostHTTPAddr:   s.addr,
		ParentNIC:      s.parentNIC,
		RuntimeBase:    s.runtimeBase,
		PersistentBase: s.persistentBase,
		Namespaces:     namespaces,
	}
	if s.jobManager != nil {
		jobs, err := s.jobManager.Snapshot()
		if err != nil {
			data.JobsError = err.Error()
		} else {
			data.Jobs = jobs
		}
	}
	return data
}

func lookupNamespaceARPTable(namespaceName, ifName string) ([]hostARPEntryView, error) {
	ns, err := netns.GetFromName(namespaceName)
	if err != nil {
		return nil, fmt.Errorf("arp lookup namespace %q: %w", namespaceName, err)
	}
	defer ns.Close()

	handle, err := netlink.NewHandleAt(ns)
	if err != nil {
		return nil, fmt.Errorf("arp open namespace %q: %w", namespaceName, err)
	}
	defer handle.Delete()

	link, err := handle.LinkByName(ifName)
	if err != nil {
		return nil, fmt.Errorf("arp lookup link %q in %q: %w", ifName, namespaceName, err)
	}

	neighbors, err := handle.NeighList(link.Attrs().Index, netlink.FAMILY_V4)
	if err != nil {
		return nil, fmt.Errorf("arp list neighbors on %q in %q: %w", ifName, namespaceName, err)
	}

	entries := make([]hostARPEntryView, 0, len(neighbors))
	for _, neighbor := range neighbors {
		if neighbor.IP == nil || neighbor.HardwareAddr == nil {
			continue
		}
		entries = append(entries, hostARPEntryView{
			IP:  neighbor.IP.String(),
			MAC: neighbor.HardwareAddr.String(),
		})
	}

	sort.Slice(entries, func(i, j int) bool {
		if entries[i].IP != entries[j].IP {
			return entries[i].IP < entries[j].IP
		}
		return entries[i].MAC < entries[j].MAC
	})

	return entries, nil
}

func lookupNamespaceNICStatistics(namespaceName, ifName string) (hostNICStatisticsView, error) {
	ns, err := netns.GetFromName(namespaceName)
	if err != nil {
		return hostNICStatisticsView{}, fmt.Errorf("statistics lookup namespace %q: %w", namespaceName, err)
	}
	defer ns.Close()

	handle, err := netlink.NewHandleAt(ns)
	if err != nil {
		return hostNICStatisticsView{}, fmt.Errorf("statistics open namespace %q: %w", namespaceName, err)
	}
	defer handle.Delete()

	link, err := handle.LinkByName(ifName)
	if err != nil {
		return hostNICStatisticsView{}, fmt.Errorf("statistics lookup link %q in %q: %w", ifName, namespaceName, err)
	}

	stats := link.Attrs().Statistics
	if stats == nil {
		return hostNICStatisticsView{}, fmt.Errorf("statistics unavailable for %q in %q", ifName, namespaceName)
	}

	return hostNICStatisticsView{
		RxBytes:   stats.RxBytes,
		TxBytes:   stats.TxBytes,
		RxPackets: stats.RxPackets,
		TxPackets: stats.TxPackets,
		RxErrors:  stats.RxErrors,
		TxErrors:  stats.TxErrors,
		RxDropped: stats.RxDropped,
		TxDropped: stats.TxDropped,
	}, nil
}

func (s *hostDashboardService) routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/", s.handleIndex)
	mux.HandleFunc("/probes", s.handleProbesPage)
	mux.HandleFunc("/sftp-jobs", s.handleSFTPJobsPage)
	mux.HandleFunc("/configs", s.handleConfigsPage)
	mux.HandleFunc("/ping", s.handlePing)
	mux.HandleFunc("/tcp-check", s.handleTCPCheck)
	mux.HandleFunc("/sftp-list", s.handleSFTPList)
	mux.HandleFunc("/sftp-jobs/create", s.handleCreateSFTPJob)
	mux.HandleFunc("/sftp-jobs/start", s.handleStartSFTPJob)
	mux.HandleFunc("/sftp-jobs/stop", s.handleStopSFTPJob)
	mux.HandleFunc("/sftp-jobs/delete", s.handleDeleteSFTPJob)
	mux.HandleFunc("/healthz", s.handleHealthz)
	mux.HandleFunc("/api/namespaces", s.handleNamespacesAPI)
	return mux
}

func (s *hostDashboardService) handleIndex(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	s.renderPage(w, s.snapshotPageWithContext(r.Context(), hostDashboardPageOverview))
}

func (s *hostDashboardService) handleProbesPage(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/probes" {
		http.NotFound(w, r)
		return
	}
	s.renderPage(w, s.snapshotPageWithContext(r.Context(), hostDashboardPageProbes))
}

func (s *hostDashboardService) handleSFTPJobsPage(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/sftp-jobs" {
		http.NotFound(w, r)
		return
	}
	s.renderPage(w, s.snapshotPageWithContext(r.Context(), hostDashboardPageJobs))
}

func (s *hostDashboardService) handleConfigsPage(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/configs" {
		http.NotFound(w, r)
		return
	}
	s.renderPage(w, s.snapshotPageWithContext(r.Context(), hostDashboardPageConfigs))
}

func (s *hostDashboardService) snapshotPageWithContext(ctx context.Context, page string) hostDashboardData {
	data := s.snapshotWithContext(ctx)
	applyDashboardPageMetadata(&data, page)
	return data
}

func (s *hostDashboardService) renderPage(w http.ResponseWriter, data hostDashboardData) {
	if data.CurrentPage == "" {
		applyDashboardPageMetadata(&data, hostDashboardPageOverview)
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := hostDashboardTemplate.ExecuteTemplate(w, "layout", data); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func (s *hostDashboardService) handlePing(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	namespaceName := strings.TrimSpace(r.FormValue("namespace"))
	targetIP := strings.TrimSpace(r.FormValue("target_ip"))
	result := &hostPingResultView{
		Namespace: namespaceName,
		TargetIP:  targetIP,
	}

	switch {
	case namespaceName == "":
		result.Error = "namespace is required"
	case !s.hasNamespace(namespaceName):
		result.Error = fmt.Sprintf("unknown namespace %q", namespaceName)
	case net.ParseIP(targetIP) == nil:
		result.Error = fmt.Sprintf("invalid IP address %q", targetIP)
	default:
		output, err := s.ping(namespaceName, targetIP)
		result.Output = output
		if err != nil {
			result.Error = err.Error()
		} else {
			result.Success = true
		}
	}

	data := s.snapshotPageWithContext(r.Context(), hostDashboardPageProbes)
	data.SelectedPingNamespace = namespaceName
	data.PingTargetIP = targetIP
	data.PingResult = result
	s.renderPage(w, data)
}

func (s *hostDashboardService) handleTCPCheck(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	namespaceName := strings.TrimSpace(r.FormValue("namespace"))
	targetIP := strings.TrimSpace(r.FormValue("target_ip"))
	portRaw := strings.TrimSpace(r.FormValue("port"))
	result := &hostTCPResultView{
		Namespace: namespaceName,
		TargetIP:  targetIP,
	}

	switch {
	case namespaceName == "":
		result.Error = "namespace is required"
	case !s.hasNamespace(namespaceName):
		result.Error = fmt.Sprintf("unknown namespace %q", namespaceName)
	case net.ParseIP(targetIP) == nil:
		result.Error = fmt.Sprintf("invalid IP address %q", targetIP)
	default:
		port, err := strconv.Atoi(portRaw)
		if err != nil || port < 1 || port > 65535 {
			result.Error = fmt.Sprintf("invalid TCP port %q", portRaw)
		} else {
			result.Port = port
			output, err := s.checkTCPPort(namespaceName, targetIP, port)
			result.Output = output
			if err != nil {
				result.Error = err.Error()
			} else {
				result.Success = true
			}
		}
	}

	data := s.snapshotPageWithContext(r.Context(), hostDashboardPageProbes)
	data.SelectedTCPNamespace = namespaceName
	data.TCPTargetIP = targetIP
	data.TCPTargetPort = portRaw
	data.TCPCheckResult = result
	s.renderPage(w, data)
}

func (s *hostDashboardService) handleSFTPList(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	namespaceName := strings.TrimSpace(r.FormValue("namespace"))
	serverHost := strings.Trim(strings.TrimSpace(r.FormValue("server_host")), "[]")
	portRaw := strings.TrimSpace(r.FormValue("port"))
	username := strings.TrimSpace(r.FormValue("username"))
	password := r.FormValue("password")
	directory := strings.TrimSpace(r.FormValue("directory"))
	result := &hostSFTPResultView{
		Namespace: namespaceName,
		Server:    serverHost,
		Username:  username,
		Directory: directory,
	}

	switch {
	case namespaceName == "":
		result.Error = "namespace is required"
	case !s.hasNamespace(namespaceName):
		result.Error = fmt.Sprintf("unknown namespace %q", namespaceName)
	case serverHost == "":
		result.Error = "server host is required"
	case username == "":
		result.Error = "user name is required"
	case password == "":
		result.Error = "password is required"
	default:
		port, err := strconv.Atoi(portRaw)
		if err != nil || port < 1 || port > 65535 {
			result.Error = fmt.Sprintf("invalid TCP port %q", portRaw)
		} else {
			result.Port = port
			entries, err := s.listSFTP(namespaceName, SFTPListRequest{
				Connection: SFTPConnectionInfo{
					Address:               net.JoinHostPort(serverHost, strconv.Itoa(port)),
					Username:              username,
					Password:              password,
					InsecureIgnoreHostKey: true,
				},
				Directory: directory,
			})
			if err != nil {
				result.Error = err.Error()
			} else {
				result.Success = true
				result.Entries = entries.Entries
			}
		}
	}

	data := s.snapshotPageWithContext(r.Context(), hostDashboardPageProbes)
	data.SelectedSFTPNamespace = namespaceName
	data.SFTPServerHost = serverHost
	data.SFTPServerPort = portRaw
	data.SFTPUsername = username
	data.SFTPDirectory = directory
	data.SFTPListResult = result
	s.renderPage(w, data)
}

func (s *hostDashboardService) handleCreateSFTPJob(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	form := hostSFTPSyncJobFormData{
		FromKind:      normalizeSFTPEndpointKind(r.FormValue("from_kind")),
		FromNamespace: strings.TrimSpace(r.FormValue("from_namespace")),
		FromHost:      strings.Trim(strings.TrimSpace(r.FormValue("from_host")), "[]"),
		FromPort:      strings.TrimSpace(r.FormValue("from_port")),
		FromUsername:  strings.TrimSpace(r.FormValue("from_username")),
		FromDirectory: strings.TrimSpace(r.FormValue("from_directory")),
		ToKind:        normalizeSFTPEndpointKind(r.FormValue("to_kind")),
		ToNamespace:   strings.TrimSpace(r.FormValue("to_namespace")),
		ToHost:        strings.Trim(strings.TrimSpace(r.FormValue("to_host")), "[]"),
		ToPort:        strings.TrimSpace(r.FormValue("to_port")),
		ToUsername:    strings.TrimSpace(r.FormValue("to_username")),
		ToDirectory:   strings.TrimSpace(r.FormValue("to_directory")),
		Interval:      strings.TrimSpace(r.FormValue("interval")),
	}
	fromPassword := r.FormValue("from_password")
	toPassword := r.FormValue("to_password")

	data := s.snapshotPageWithContext(r.Context(), hostDashboardPageJobs)
	data.SFTPJobForm = form

	if s.jobManager == nil {
		data.SFTPJobError = "sftp job manager unavailable"
		s.renderPage(w, data)
		return
	}

	interval, err := parseDashboardJobInterval(form.Interval)
	if err != nil {
		data.SFTPJobError = err.Error()
		s.renderPage(w, data)
		return
	}

	fromPort := 0
	if form.FromKind == sftpEndpointKindClient {
		fromPort, err = strconv.Atoi(form.FromPort)
		if err != nil || fromPort < 1 || fromPort > 65535 {
			data.SFTPJobError = fmt.Sprintf("invalid source TCP port %q", form.FromPort)
			s.renderPage(w, data)
			return
		}
	}

	toPort := 0
	if form.ToKind == sftpEndpointKindClient {
		toPort, err = strconv.Atoi(form.ToPort)
		if err != nil || toPort < 1 || toPort > 65535 {
			data.SFTPJobError = fmt.Sprintf("invalid destination TCP port %q", form.ToPort)
			s.renderPage(w, data)
			return
		}
	}

	job, err := s.jobManager.CreateJob(sftpSyncJobSpec{
		From: sftpEndpointConfig{
			Kind:      form.FromKind,
			Namespace: form.FromNamespace,
			Host:      form.FromHost,
			Port:      fromPort,
			Username:  form.FromUsername,
			Password:  fromPassword,
			Directory: form.FromDirectory,
		},
		To: sftpEndpointConfig{
			Kind:      form.ToKind,
			Namespace: form.ToNamespace,
			Host:      form.ToHost,
			Port:      toPort,
			Username:  form.ToUsername,
			Password:  toPassword,
			Directory: form.ToDirectory,
		},
		Interval: interval,
	})
	if err != nil {
		data.SFTPJobError = err.Error()
		s.renderPage(w, data)
		return
	}

	data = s.snapshotPageWithContext(r.Context(), hostDashboardPageJobs)
	data.SFTPJobMessage = fmt.Sprintf("Created SFTP sync job #%d. Start it when you are ready.", job.ID)
	s.renderPage(w, data)
}

func (s *hostDashboardService) handleStartSFTPJob(w http.ResponseWriter, r *http.Request) {
	s.handleSFTPJobStateChange(w, r, true)
}

func (s *hostDashboardService) handleStopSFTPJob(w http.ResponseWriter, r *http.Request) {
	s.handleSFTPJobStateChange(w, r, false)
}

func (s *hostDashboardService) handleDeleteSFTPJob(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	data := s.snapshotPageWithContext(r.Context(), hostDashboardPageJobs)
	if s.jobManager == nil {
		data.SFTPJobError = "sftp job manager unavailable"
		s.renderPage(w, data)
		return
	}

	jobID, err := parseDashboardJobID(strings.TrimSpace(r.FormValue("job_id")))
	if err != nil {
		data.SFTPJobError = err.Error()
		s.renderPage(w, data)
		return
	}

	job, err := s.jobManager.DeleteJob(jobID)
	if err != nil {
		data.SFTPJobError = err.Error()
	} else {
		data = s.snapshotPageWithContext(r.Context(), hostDashboardPageJobs)
		data.SFTPJobMessage = fmt.Sprintf("Deleted SFTP sync job #%d (%s -> %s).", job.ID, job.From.Namespace, job.To.Namespace)
	}
	s.renderPage(w, data)
}

func (s *hostDashboardService) handleSFTPJobStateChange(w http.ResponseWriter, r *http.Request, start bool) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	data := s.snapshotPageWithContext(r.Context(), hostDashboardPageJobs)
	if s.jobManager == nil {
		data.SFTPJobError = "sftp job manager unavailable"
		s.renderPage(w, data)
		return
	}

	jobID, err := parseDashboardJobID(strings.TrimSpace(r.FormValue("job_id")))
	if err != nil {
		data.SFTPJobError = err.Error()
		s.renderPage(w, data)
		return
	}

	if start {
		job, err := s.jobManager.StartJob(jobID)
		if err != nil {
			data.SFTPJobError = err.Error()
		} else {
			data = s.snapshotPageWithContext(r.Context(), hostDashboardPageJobs)
			data.SFTPJobMessage = fmt.Sprintf("Started SFTP sync job #%d (%s -> %s).", job.ID, job.From.Namespace, job.To.Namespace)
		}
		s.renderPage(w, data)
		return
	}

	job, err := s.jobManager.StopJob(jobID)
	if err != nil {
		data.SFTPJobError = err.Error()
	} else {
		data = s.snapshotPageWithContext(r.Context(), hostDashboardPageJobs)
		data.SFTPJobMessage = fmt.Sprintf("Stopped SFTP sync job #%d (%s -> %s).", job.ID, job.From.Namespace, job.To.Namespace)
	}
	s.renderPage(w, data)
}

func (s *hostDashboardService) handleHealthz(w http.ResponseWriter, _ *http.Request) {
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("ok\n"))
}

func (s *hostDashboardService) handleNamespacesAPI(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(s.snapshotWithContext(r.Context())); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func (s *hostDashboardService) hasNamespace(namespaceName string) bool {
	return s.pluginForNamespace(namespaceName) != nil
}

func (s *hostDashboardService) pluginForNamespace(namespaceName string) *runningPlugin {
	for _, plugin := range s.plugins {
		if plugin != nil && plugin.cfg.Name == namespaceName {
			return plugin
		}
	}
	return nil
}

func (s *hostDashboardService) ping(namespaceName, targetIP string) (string, error) {
	if s.pingFunc != nil {
		return s.pingFunc(namespaceName, targetIP)
	}
	return pingNamespaceAddress(namespaceName, targetIP)
}

func (s *hostDashboardService) checkTCPPort(namespaceName, targetIP string, port int) (string, error) {
	if s.tcpCheckFunc != nil {
		return s.tcpCheckFunc(namespaceName, targetIP, port)
	}

	plugin := s.pluginForNamespace(namespaceName)
	if plugin == nil {
		return "", fmt.Errorf("unknown namespace %q", namespaceName)
	}
	if plugin.rpc == nil {
		return "", fmt.Errorf("plugin rpc for namespace %q is unavailable", namespaceName)
	}
	return plugin.rpc.CheckTCPPort(targetIP, port)
}

func (s *hostDashboardService) listSFTP(namespaceName string, req SFTPListRequest) (*SFTPListResponse, error) {
	plugin := s.pluginForNamespace(namespaceName)
	if plugin == nil {
		return nil, fmt.Errorf("unknown namespace %q", namespaceName)
	}
	if plugin.rpc == nil {
		return nil, fmt.Errorf("plugin rpc for namespace %q is unavailable", namespaceName)
	}
	return plugin.rpc.SFTPList(req)
}

func parseDashboardJobID(raw string) (int64, error) {
	if raw == "" {
		return 0, errors.New("job id is required")
	}
	jobID, err := strconv.ParseInt(raw, 10, 64)
	if err != nil || jobID < 1 {
		return 0, fmt.Errorf("invalid job id %q", raw)
	}
	return jobID, nil
}

func withNamedNamespace(namespaceName string, fn func() error) error {
	ns, err := getNamedNamespaceHandle(namespaceName)
	if err != nil {
		return fmt.Errorf("lookup namespace %q: %w", namespaceName, err)
	}
	defer ns.Close()

	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	original, err := getCurrentNamespace()
	if err != nil {
		return fmt.Errorf("get current namespace: %w", err)
	}
	defer original.Close()

	if err := setCurrentNamespace(ns); err != nil {
		return fmt.Errorf("enter namespace %q: %w", namespaceName, err)
	}

	err = fn()
	restoreErr := setCurrentNamespace(original)
	if err != nil {
		if restoreErr != nil {
			return fmt.Errorf("%w; restore original namespace: %v", err, restoreErr)
		}
		return err
	}
	if restoreErr != nil {
		return fmt.Errorf("restore original namespace after entering %q: %w", namespaceName, restoreErr)
	}
	return nil
}

func pingNamespaceAddress(namespaceName, targetIP string) (string, error) {
	ip := net.ParseIP(targetIP)
	if ip == nil {
		return "", fmt.Errorf("invalid IP address %q", targetIP)
	}

	pinger := newNamespacePinger(targetIP)
	if ip.To4() != nil {
		pinger.SetNetwork("ip4")
	} else {
		pinger.SetNetwork("ip6")
	}
	pinger.SetPrivileged(true)
	pinger.SetCount(1)
	pinger.SetInterval(200 * time.Millisecond)
	pinger.SetTimeout(2 * time.Second)

	var recvLines []string
	pinger.SetOnRecv(func(pkt namespacePingPacket) {
		recvLines = append(recvLines, fmt.Sprintf("%d bytes from %s: icmp_seq=%d time=%s", pkt.NBytes, pkt.IPAddr, pkt.Seq, pkt.Rtt))
	})

	err := runInNamedNamespace(namespaceName, pinger.Run)
	stats := pinger.Statistics()
	targetAddr := stats.Addr
	if targetAddr == "" {
		targetAddr = targetIP
	}

	summary := []string{
		fmt.Sprintf("PING %s:", targetAddr),
	}
	summary = append(summary, recvLines...)
	summary = append(summary, fmt.Sprintf("%d packets transmitted, %d packets received, %.0f%% packet loss", stats.PacketsSent, stats.PacketsRecv, stats.PacketLoss))
	if stats.PacketsRecv > 0 {
		summary = append(summary, fmt.Sprintf("round-trip min/avg/max/stddev = %s/%s/%s/%s", stats.MinRtt, stats.AvgRtt, stats.MaxRtt, stats.StdDevRtt))
	}
	output := strings.Join(summary, "\n")

	if err != nil {
		if output == "" {
			output = fmt.Sprintf("ping to %s from %s failed", targetIP, namespaceName)
		}
		return output, fmt.Errorf("ping %s from %s failed: %w", targetIP, namespaceName, err)
	}
	if stats.PacketsRecv == 0 {
		return output, errors.New("ping timed out")
	}
	return output, nil
}

func checkCurrentNamespaceTCPPort(namespaceName, targetIP string, port int) (string, error) {
	ip := net.ParseIP(targetIP)
	if ip == nil {
		return "", fmt.Errorf("invalid IP address %q", targetIP)
	}
	if port < 1 || port > 65535 {
		return "", fmt.Errorf("invalid TCP port %d", port)
	}

	network := "tcp4"
	if ip.To4() == nil {
		network = "tcp6"
	}

	addr := net.JoinHostPort(targetIP, strconv.Itoa(port))
	conn, err := (&net.Dialer{Timeout: 3 * time.Second}).Dial(network, addr)
	if err != nil {
		return fmt.Sprintf("tcp connect to %s failed", addr), fmt.Errorf("tcp connect to %s from %s failed: %w", addr, namespaceName, err)
	}
	_ = conn.Close()

	return fmt.Sprintf("tcp connect to %s from %s succeeded", addr, namespaceName), nil
}

func startHostDashboard(addr, parentNIC, runtimeBase, persistentBase string, plugins []*runningPlugin, jobManager *sftpSyncJobManager) (*http.Server, string, error) {
	service := &hostDashboardService{
		addr:           addr,
		parentNIC:      parentNIC,
		runtimeBase:    runtimeBase,
		persistentBase: persistentBase,
		plugins:        plugins,
		jobManager:     jobManager,
	}

	listener, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, "", err
	}

	server := &http.Server{
		Addr:              addr,
		Handler:           service.routes(),
		ReadHeaderTimeout: 5 * time.Second,
	}

	go func() {
		err := server.Serve(listener)
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Printf("host dashboard error: %v", err)
		}
	}()

	return server, listener.Addr().String(), nil
}
