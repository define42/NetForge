//go:build linux

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"log"
	"net"
	"net/http"
	"os/exec"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

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
	HostHTTPAddr          string              `json:"host_http_addr"`
	ParentNIC             string              `json:"parent_nic"`
	RuntimeBase           string              `json:"runtime_base"`
	Namespaces            []hostNamespaceView `json:"namespaces"`
	SelectedPingNamespace string              `json:"selected_ping_namespace,omitempty"`
	PingTargetIP          string              `json:"ping_target_ip,omitempty"`
	PingResult            *hostPingResultView `json:"ping_result,omitempty"`
	SelectedTCPNamespace  string              `json:"selected_tcp_namespace,omitempty"`
	TCPTargetIP           string              `json:"tcp_target_ip,omitempty"`
	TCPTargetPort         string              `json:"tcp_target_port,omitempty"`
	TCPCheckResult        *hostTCPResultView  `json:"tcp_check_result,omitempty"`
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

type hostDashboardService struct {
	addr         string
	parentNIC    string
	runtimeBase  string
	plugins      []*runningPlugin
	statsLookup  func(namespaceName, ifName string) (hostNICStatisticsView, error)
	arpLookup    func(namespaceName, ifName string) ([]hostARPEntryView, error)
	pingFunc     func(namespaceName, targetIP string) (string, error)
	tcpCheckFunc func(namespaceName, targetIP string, port int) (string, error)
}

var dashboardSnapshotTaskTimeout = 750 * time.Millisecond

type dashboardTaskResult[T any] struct {
	value T
	err   error
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

var hostDashboardTemplate = template.Must(template.New("host-dashboard").Parse(`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>NetForge Dashboard</title>
<style>
body {
	font-family: "Segoe UI", sans-serif;
	margin: 0;
	padding: 2rem;
	background: linear-gradient(180deg, #f6f4ee 0%, #eef2f6 100%);
	color: #183153;
}
h1 {
	margin-top: 0;
}
.meta {
	display: grid;
	grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
	gap: 1rem;
	margin: 1.5rem 0;
}
.card, table {
	background: rgba(255, 255, 255, 0.92);
	border: 1px solid #d7e0ea;
	border-radius: 16px;
	box-shadow: 0 16px 40px rgba(24, 49, 83, 0.08);
}
.card {
	padding: 1rem 1.2rem;
}
table {
	width: 100%;
	border-collapse: collapse;
	overflow: hidden;
}
th, td {
	padding: 0.85rem 1rem;
	text-align: left;
	vertical-align: top;
	border-bottom: 1px solid #e3e9f0;
}
th {
	background: #183153;
	color: #fff;
	font-weight: 600;
}
tr:last-child td {
	border-bottom: 0;
}
.status-ok {
	color: #0d6b3c;
	font-weight: 600;
}
.status-bad {
	color: #9a3412;
	font-weight: 600;
}
code {
	font-size: 0.95em;
}
form {
	margin: 0;
}
.ping-card {
	margin-bottom: 1.5rem;
}
.probe-grid {
	display: grid;
	grid-template-columns: repeat(auto-fit, minmax(280px, 1fr));
	gap: 1rem;
}
.probe-pane h2 {
	margin: 0 0 0.85rem;
	font-size: 1.1rem;
}
.ping-form {
	display: grid;
	grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
	gap: 0.85rem;
	align-items: end;
}
.ping-form label {
	display: block;
	font-weight: 600;
}
.ping-form input,
.ping-form select,
.ping-form button {
	width: 100%;
	box-sizing: border-box;
	margin-top: 0.35rem;
	padding: 0.7rem 0.8rem;
	border-radius: 10px;
	border: 1px solid #c8d3de;
	font: inherit;
}
.ping-form button {
	background: #183153;
	color: #fff;
	cursor: pointer;
	font-weight: 600;
}
.ping-form button:hover {
	background: #24456e;
}
pre {
	margin: 0.85rem 0 0;
	padding: 0.9rem 1rem;
	background: #0f172a;
	color: #e2e8f0;
	border-radius: 12px;
	overflow-x: auto;
	white-space: pre-wrap;
}
</style>
</head>
<body>
<h1>NetForge Dashboard</h1>
<div class="meta">
<div class="card"><strong>Host dashboard:</strong><br><code>{{.HostHTTPAddr}}</code></div>
<div class="card"><strong>Parent NIC:</strong><br><code>{{.ParentNIC}}</code></div>
<div class="card"><strong>Runtime base:</strong><br><code>{{.RuntimeBase}}</code></div>
</div>
<div class="card ping-card">
<div class="probe-grid">
<div class="probe-pane">
<h2>Ping Target</h2>
<form class="ping-form" method="post" action="/ping">
<label>Namespace
<select name="namespace" required>
<option value="">Select namespace</option>
{{range .Namespaces}}
<option value="{{.Name}}" {{if eq $.SelectedPingNamespace .Name}}selected{{end}}>{{.Name}}</option>
{{end}}
</select>
</label>
<label>Target IP
<input type="text" name="target_ip" placeholder="192.168.1.1" value="{{.PingTargetIP}}" required>
</label>
<div>
<button type="submit">Ping From Namespace</button>
</div>
</form>
{{if .PingResult}}
<div style="margin-top: 1rem;">
{{if .PingResult.Success}}
<div class="status-ok">Ping succeeded: <code>{{.PingResult.Namespace}}</code> -> <code>{{.PingResult.TargetIP}}</code></div>
{{else}}
<div class="status-bad">Ping failed: <code>{{.PingResult.Namespace}}</code> -> <code>{{.PingResult.TargetIP}}</code>{{if .PingResult.Error}}<br>{{.PingResult.Error}}{{end}}</div>
{{end}}
{{if .PingResult.Output}}<pre>{{.PingResult.Output}}</pre>{{end}}
</div>
{{end}}
</div>
<div class="probe-pane">
<h2>TCP Port Check</h2>
<form class="ping-form" method="post" action="/tcp-check">
<label>Namespace
<select name="namespace" required>
<option value="">Select namespace</option>
{{range .Namespaces}}
<option value="{{.Name}}" {{if eq $.SelectedTCPNamespace .Name}}selected{{end}}>{{.Name}}</option>
{{end}}
</select>
</label>
<label>Target IP
<input type="text" name="target_ip" placeholder="192.168.1.1" value="{{.TCPTargetIP}}" required>
</label>
<label>TCP Port
<input type="number" name="port" min="1" max="65535" placeholder="80" value="{{.TCPTargetPort}}" required>
</label>
<div>
<button type="submit">Test TCP Port</button>
</div>
</form>
{{if .TCPCheckResult}}
<div style="margin-top: 1rem;">
{{if .TCPCheckResult.Success}}
<div class="status-ok">TCP port is open: <code>{{.TCPCheckResult.Namespace}}</code> -> <code>{{.TCPCheckResult.TargetIP}}:{{.TCPCheckResult.Port}}</code></div>
{{else}}
<div class="status-bad">TCP port check failed: <code>{{.TCPCheckResult.Namespace}}</code> -> <code>{{.TCPCheckResult.TargetIP}}:{{.TCPCheckResult.Port}}</code>{{if .TCPCheckResult.Error}}<br>{{.TCPCheckResult.Error}}{{end}}</div>
{{end}}
{{if .TCPCheckResult.Output}}<pre>{{.TCPCheckResult.Output}}</pre>{{end}}
</div>
{{end}}
</div>
</div>
</div>
<table>
<thead>
<tr>
<th>Namespace</th>
<th>VLAN</th>
<th>Interface</th>
<th>IP / Gateway</th>
<th>MAC</th>
<th>Plugin HTTP</th>
<th>Open TCP</th>
<th>ICMP</th>
<th>ARP Table</th>
<th>NIC Statistics</th>
<th>Status</th>
</tr>
</thead>
<tbody>
{{range .Namespaces}}
<tr>
<td><code>{{.Name}}</code></td>
<td>{{.VLANID}}</td>
<td><code>{{.Interface}}</code></td>
<td><code>{{.IPCIDR}}</code><br><code>{{if .Gateway}}{{.Gateway}}{{else}}none{{end}}</code></td>
<td><code>{{.MAC}}</code></td>
<td><code>{{.PluginHTTPAddr}}</code><br>configured port {{.ListenPort}}</td>
<td><code>{{if .OpenPorts}}{{range $i, $port := .OpenPorts}}{{if $i}}, {{end}}{{$port}}{{end}}{{else}}none{{end}}</code></td>
<td><code>{{if .AllowICMP}}icmp enabled{{else}}icmp disabled{{end}}</code></td>
<td>
{{if .ARPError}}
<span class="status-bad">{{.ARPError}}</span>
{{else if .ARPEntries}}
{{range .ARPEntries}}
<code>{{.IP}}</code><br><code>{{.MAC}}</code><br>
{{end}}
{{else}}
<code>empty</code>
{{end}}
</td>
<td>
{{if .StatisticsError}}
<span class="status-bad">{{.StatisticsError}}</span>
{{else}}
<code>rx bytes {{.Statistics.RxBytes}}</code><br>
<code>rx pkts {{.Statistics.RxPackets}}</code><br>
<code>rx errs {{.Statistics.RxErrors}}</code><br>
<code>rx drop {{.Statistics.RxDropped}}</code><br>
<code>tx bytes {{.Statistics.TxBytes}}</code><br>
<code>tx pkts {{.Statistics.TxPackets}}</code><br>
<code>tx errs {{.Statistics.TxErrors}}</code><br>
<code>tx drop {{.Statistics.TxDropped}}</code>
{{end}}
</td>
<td>
{{if .Error}}
<span class="status-bad">{{.Error}}</span>
{{else if .HTTPRunning}}
<span class="status-ok">running</span><br>{{.Message}}
{{else}}
<span class="status-bad">stopped</span><br>{{.Message}}
{{end}}
</td>
</tr>
{{end}}
</tbody>
</table>
</body>
</html>`))

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

	return hostDashboardData{
		HostHTTPAddr: s.addr,
		ParentNIC:    s.parentNIC,
		RuntimeBase:  s.runtimeBase,
		Namespaces:   namespaces,
	}
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
	mux.HandleFunc("/ping", s.handlePing)
	mux.HandleFunc("/tcp-check", s.handleTCPCheck)
	mux.HandleFunc("/healthz", s.handleHealthz)
	mux.HandleFunc("/api/namespaces", s.handleNamespacesAPI)
	return mux
}

func (s *hostDashboardService) handleIndex(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	s.renderIndex(w, s.snapshotWithContext(r.Context()))
}

func (s *hostDashboardService) renderIndex(w http.ResponseWriter, data hostDashboardData) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := hostDashboardTemplate.Execute(w, data); err != nil {
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

	data := s.snapshotWithContext(r.Context())
	data.SelectedPingNamespace = namespaceName
	data.PingTargetIP = targetIP
	data.PingResult = result
	s.renderIndex(w, data)
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

	data := s.snapshotWithContext(r.Context())
	data.SelectedTCPNamespace = namespaceName
	data.TCPTargetIP = targetIP
	data.TCPTargetPort = portRaw
	data.TCPCheckResult = result
	s.renderIndex(w, data)
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
	for _, plugin := range s.plugins {
		if plugin != nil && plugin.cfg.Name == namespaceName {
			return true
		}
	}
	return false
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
	return checkNamespaceTCPPort(namespaceName, targetIP, port)
}

func pingNamespaceAddress(namespaceName, targetIP string) (string, error) {
	ip := net.ParseIP(targetIP)
	if ip == nil {
		return "", fmt.Errorf("invalid IP address %q", targetIP)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	args := []string{"-n", "-c", "1", "-W", "2"}
	if ip.To4() != nil {
		args = append(args, "-4")
	} else {
		args = append(args, "-6")
	}
	args = append(args, targetIP)

	cmd := exec.CommandContext(ctx, "ping", args...)
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := startCmdInNamedNamespace(cmd, namespaceName); err != nil {
		return "", fmt.Errorf("start ping in namespace %q: %w", namespaceName, err)
	}

	err := cmd.Wait()
	output := strings.TrimSpace(stdout.String())
	if stderr.Len() > 0 {
		if output != "" {
			output += "\n"
		}
		output += strings.TrimSpace(stderr.String())
	}

	if errors.Is(ctx.Err(), context.DeadlineExceeded) {
		if output == "" {
			output = "ping timed out"
		}
		return output, errors.New("ping timed out")
	}
	if err != nil {
		if output == "" {
			output = fmt.Sprintf("ping to %s from %s failed", targetIP, namespaceName)
		}
		return output, fmt.Errorf("ping %s from %s failed: %w", targetIP, namespaceName, err)
	}
	if output == "" {
		output = fmt.Sprintf("ping to %s from %s succeeded", targetIP, namespaceName)
	}
	return output, nil
}

func checkNamespaceTCPPort(namespaceName, targetIP string, port int) (string, error) {
	ip := net.ParseIP(targetIP)
	if ip == nil {
		return "", fmt.Errorf("invalid IP address %q", targetIP)
	}
	if port < 1 || port > 65535 {
		return "", fmt.Errorf("invalid TCP port %d", port)
	}

	ns, err := netns.GetFromName(namespaceName)
	if err != nil {
		return "", fmt.Errorf("lookup namespace %q: %w", namespaceName, err)
	}
	defer ns.Close()

	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	original, err := netns.Get()
	if err != nil {
		return "", fmt.Errorf("get current namespace: %w", err)
	}
	defer original.Close()

	if err := netns.Set(ns); err != nil {
		return "", fmt.Errorf("enter namespace %q: %w", namespaceName, err)
	}
	defer netns.Set(original)

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

func startHostDashboard(addr, parentNIC, runtimeBase string, plugins []*runningPlugin) (*http.Server, string, error) {
	service := &hostDashboardService{
		addr:        addr,
		parentNIC:   parentNIC,
		runtimeBase: runtimeBase,
		plugins:     plugins,
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
