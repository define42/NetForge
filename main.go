//go:build linux

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"io"
	"log"
	"net"
	"net/http"
	"net/rpc"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/google/nftables"
	"github.com/google/nftables/binaryutil"
	"github.com/google/nftables/expr"
	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/go-plugin"
	"github.com/hashicorp/go-plugin/runner"
	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netns"
	"golang.org/x/sys/unix"
)

const pluginName = "namespace_service"

type NSConfig struct {
	Name       string `json:"name"`
	VLANID     int    `json:"vlan_id"`
	IfName     string `json:"if_name"`
	IPCIDR     string `json:"ip_cidr"`
	MAC        string `json:"mac"`
	Gateway    string `json:"gateway"`
	ListenPort int    `json:"listen_port"`
	OpenPort   int    `json:"open_port"`
	AllowICMP  bool   `json:"allow_icmp"`
}

type PluginConfig struct {
	Namespace string `json:"namespace"`
	Interface string `json:"interface"`
	IPCIDR    string `json:"ip_cidr"`
	MAC       string `json:"mac"`
	Gateway   string `json:"gateway"`
	OpenPort  int    `json:"open_port"`
	AllowICMP bool   `json:"allow_icmp"`
}

type DescribeResponse struct {
	Namespace string
	HTTPAddr  string
	Message   string
}

type StartHTTPResponse struct {
	HTTPAddr string
}

type StatusResponse struct {
	Namespace   string
	Interface   string
	IPCIDR      string
	MAC         string
	Gateway     string
	OpenPort    int
	AllowICMP   bool
	HTTPAddr    string
	HTTPRunning bool
}

type NamespaceService interface {
	Describe() (*DescribeResponse, error)
	StartHTTP(port int) (*StartHTTPResponse, error)
	StopHTTP() error
	Status() (*StatusResponse, error)
}

var handshake = plugin.HandshakeConfig{
	ProtocolVersion:  1,
	MagicCookieKey:   "NS_PLUGIN",
	MagicCookieValue: "namespace-service",
}

type namespaceServicePlugin struct {
	plugin.Plugin
	Impl NamespaceService
}

func (p *namespaceServicePlugin) Server(*plugin.MuxBroker) (interface{}, error) {
	return &namespaceServiceRPCServer{Impl: p.Impl}, nil
}

func (p *namespaceServicePlugin) Client(_ *plugin.MuxBroker, c *rpc.Client) (interface{}, error) {
	return &namespaceServiceRPCClient{client: c}, nil
}

var pluginMap = map[string]plugin.Plugin{
	pluginName: &namespaceServicePlugin{},
}

type namespaceServiceRPCServer struct {
	Impl NamespaceService
}

func (s *namespaceServiceRPCServer) Describe(_ struct{}, resp *DescribeResponse) error {
	out, err := s.Impl.Describe()
	if err != nil {
		return err
	}
	*resp = *out
	return nil
}

func (s *namespaceServiceRPCServer) StartHTTP(port int, resp *StartHTTPResponse) error {
	out, err := s.Impl.StartHTTP(port)
	if err != nil {
		return err
	}
	*resp = *out
	return nil
}

func (s *namespaceServiceRPCServer) StopHTTP(_ struct{}, _ *struct{}) error {
	return s.Impl.StopHTTP()
}

func (s *namespaceServiceRPCServer) Status(_ struct{}, resp *StatusResponse) error {
	out, err := s.Impl.Status()
	if err != nil {
		return err
	}
	*resp = *out
	return nil
}

type namespaceServiceRPCClient struct {
	client *rpc.Client
}

func (c *namespaceServiceRPCClient) Describe() (*DescribeResponse, error) {
	var out DescribeResponse
	err := c.client.Call("Plugin.Describe", struct{}{}, &out)
	return &out, err
}

func (c *namespaceServiceRPCClient) StartHTTP(port int) (*StartHTTPResponse, error) {
	var out StartHTTPResponse
	err := c.client.Call("Plugin.StartHTTP", port, &out)
	return &out, err
}

func (c *namespaceServiceRPCClient) StopHTTP() error {
	var out struct{}
	return c.client.Call("Plugin.StopHTTP", struct{}{}, &out)
}

func (c *namespaceServiceRPCClient) Status() (*StatusResponse, error) {
	var out StatusResponse
	err := c.client.Call("Plugin.Status", struct{}{}, &out)
	return &out, err
}

type namespaceHTTPService struct {
	cfg        PluginConfig
	mu         sync.Mutex
	httpServer *http.Server
	httpAddr   string
	port       int
}

func (s *namespaceHTTPService) Describe() (*DescribeResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	return &DescribeResponse{
		Namespace: s.cfg.Namespace,
		HTTPAddr:  s.httpAddr,
		Message:   "plugin ready",
	}, nil
}

type hostNamespaceView struct {
	Name            string                `json:"name"`
	VLANID          int                   `json:"vlan_id"`
	Interface       string                `json:"interface"`
	IPCIDR          string                `json:"ip_cidr"`
	MAC             string                `json:"mac"`
	Gateway         string                `json:"gateway"`
	ListenPort      int                   `json:"listen_port"`
	OpenPort        int                   `json:"open_port"`
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

const (
	namespaceFirewallTableName = "netforge"
	namespaceFirewallInputName = "input"
)

var (
	namedNetnsDir         = "/run/netns"
	hostLinkByName        = netlink.LinkByName
	readDirEntries        = os.ReadDir
	removeAllPath         = os.RemoveAll
	destroyNamespaceLinks = destroyNamespaceLinksInNetns
	deleteNamedNamespace  = netns.DeleteNamed
)

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
<td><code>{{if .OpenPort}}{{.OpenPort}}{{else}}none{{end}}</code></td>
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
	namespaces := make([]hostNamespaceView, 0, len(s.plugins))
	statsLookup := s.statsLookup
	if statsLookup == nil {
		statsLookup = lookupNamespaceNICStatistics
	}
	arpLookup := s.arpLookup
	if arpLookup == nil {
		arpLookup = lookupNamespaceARPTable
	}

	for _, plugin := range s.plugins {
		view := hostNamespaceView{
			Name:       plugin.cfg.Name,
			VLANID:     plugin.cfg.VLANID,
			Interface:  plugin.cfg.IfName,
			IPCIDR:     plugin.cfg.IPCIDR,
			MAC:        plugin.cfg.MAC,
			Gateway:    plugin.cfg.Gateway,
			ListenPort: plugin.cfg.ListenPort,
			OpenPort:   plugin.cfg.OpenPort,
			AllowICMP:  plugin.cfg.AllowICMP,
		}

		stats, statsErr := statsLookup(plugin.cfg.Name, plugin.cfg.IfName)
		if statsErr != nil {
			view.StatisticsError = statsErr.Error()
		} else {
			view.Statistics = stats
		}

		arpEntries, arpErr := arpLookup(plugin.cfg.Name, plugin.cfg.IfName)
		if arpErr != nil {
			view.ARPError = arpErr.Error()
		} else {
			view.ARPEntries = arpEntries
		}

		if plugin.rpc == nil {
			view.Error = "plugin rpc unavailable"
			namespaces = append(namespaces, view)
			continue
		}

		desc, descErr := plugin.rpc.Describe()
		if descErr != nil {
			view.Error = fmt.Sprintf("describe failed: %v", descErr)
			namespaces = append(namespaces, view)
			continue
		}
		view.Message = desc.Message
		if desc.HTTPAddr != "" {
			view.PluginHTTPAddr = desc.HTTPAddr
		}

		status, statusErr := plugin.rpc.Status()
		if statusErr != nil {
			view.Error = fmt.Sprintf("status failed: %v", statusErr)
			namespaces = append(namespaces, view)
			continue
		}
		if status.Interface != "" {
			view.Interface = status.Interface
		}
		if status.IPCIDR != "" {
			view.IPCIDR = status.IPCIDR
		}
		if status.MAC != "" {
			view.MAC = status.MAC
		}
		if status.Gateway != "" {
			view.Gateway = status.Gateway
		}
		if status.OpenPort != 0 {
			view.OpenPort = status.OpenPort
		}
		view.AllowICMP = status.AllowICMP
		if status.HTTPAddr != "" {
			view.PluginHTTPAddr = status.HTTPAddr
		}
		view.HTTPRunning = status.HTTPRunning
		namespaces = append(namespaces, view)
	}

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

func lookupNFTablesTable(conn *nftables.Conn, family nftables.TableFamily, name string) (*nftables.Table, error) {
	tables, err := conn.ListTablesOfFamily(family)
	if err != nil {
		return nil, err
	}
	for _, table := range tables {
		if table.Name == name {
			return table, nil
		}
	}
	return nil, nil
}

func configureNamespaceFirewall(ns netns.NsHandle, cfg NSConfig) error {
	cfg = normalizeNSConfig(cfg)

	if cfg.OpenPort < 0 || cfg.OpenPort > 65535 {
		return fmt.Errorf("invalid open port %d", cfg.OpenPort)
	}

	conn, err := nftables.New(nftables.WithNetNSFd(int(ns)))
	if err != nil {
		return fmt.Errorf("open nftables connection in %s: %w", cfg.Name, err)
	}

	existing, err := lookupNFTablesTable(conn, nftables.TableFamilyINet, namespaceFirewallTableName)
	if err != nil {
		return fmt.Errorf("list nftables tables in %s: %w", cfg.Name, err)
	}
	if existing != nil {
		conn.DelTable(existing)
		if err := conn.Flush(); err != nil {
			return fmt.Errorf("delete existing nftables table %q in %s: %w", namespaceFirewallTableName, cfg.Name, err)
		}
	}

	table := conn.AddTable(&nftables.Table{
		Family: nftables.TableFamilyINet,
		Name:   namespaceFirewallTableName,
	})
	policyDrop := nftables.ChainPolicyDrop
	input := conn.AddChain(&nftables.Chain{
		Name:     namespaceFirewallInputName,
		Table:    table,
		Type:     nftables.ChainTypeFilter,
		Hooknum:  nftables.ChainHookInput,
		Priority: nftables.ChainPriorityFilter,
		Policy:   &policyDrop,
	})

	conn.AddRule(&nftables.Rule{
		Table: table,
		Chain: input,
		Exprs: []expr.Any{
			&expr.Ct{Register: 1, Key: expr.CtKeySTATE},
			&expr.Bitwise{
				SourceRegister: 1,
				DestRegister:   1,
				Len:            4,
				Mask:           binaryutil.NativeEndian.PutUint32(expr.CtStateBitESTABLISHED | expr.CtStateBitRELATED),
				Xor:            binaryutil.NativeEndian.PutUint32(0),
			},
			&expr.Cmp{Op: expr.CmpOpNeq, Register: 1, Data: []byte{0, 0, 0, 0}},
			&expr.Verdict{Kind: expr.VerdictAccept},
		},
	})

	if cfg.AllowICMP {
		for _, proto := range []byte{unix.IPPROTO_ICMP, unix.IPPROTO_ICMPV6} {
			conn.AddRule(&nftables.Rule{
				Table: table,
				Chain: input,
				Exprs: []expr.Any{
					&expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 1},
					&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{proto}},
					&expr.Verdict{Kind: expr.VerdictAccept},
				},
			})
		}
	}

	if cfg.OpenPort != 0 {
		conn.AddRule(&nftables.Rule{
			Table: table,
			Chain: input,
			Exprs: []expr.Any{
				&expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 1},
				&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{unix.IPPROTO_TCP}},
				&expr.Payload{
					DestRegister: 1,
					Base:         expr.PayloadBaseTransportHeader,
					Offset:       2,
					Len:          2,
				},
				&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: binaryutil.BigEndian.PutUint16(uint16(cfg.OpenPort))},
				&expr.Verdict{Kind: expr.VerdictAccept},
			},
		})
	}

	if err := conn.Flush(); err != nil {
		return fmt.Errorf("install nftables rules in %s: %w", cfg.Name, err)
	}

	return nil
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
	s.renderIndex(w, s.snapshot())
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

	data := s.snapshot()
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

	data := s.snapshot()
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

func (s *hostDashboardService) handleNamespacesAPI(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(s.snapshot()); err != nil {
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

func (s *namespaceHTTPService) StartHTTP(port int) (*StartHTTPResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.httpServer != nil {
		if s.port != port {
			return nil, fmt.Errorf("http server already running on port %d", s.port)
		}
		return &StartHTTPResponse{HTTPAddr: s.httpAddr}, nil
	}

	addr := fmt.Sprintf(":%d", port)
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		_, _ = fmt.Fprintf(
			w,
			"hello from namespace=%s interface=%s ip=%s mac=%s gateway=%s remote=%s time=%s\n",
			s.cfg.Namespace,
			s.cfg.Interface,
			s.cfg.IPCIDR,
			s.cfg.MAC,
			s.cfg.Gateway,
			r.RemoteAddr,
			time.Now().Format(time.RFC3339),
		)
	})
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok\n"))
	})

	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, err
	}

	s.httpServer = &http.Server{
		Addr:              addr,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
	}
	s.port = port
	s.httpAddr = addr

	go func(server *http.Server, listener net.Listener) {
		err := server.Serve(listener)
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Printf("namespace=%s http server error: %v", s.cfg.Namespace, err)
		}
	}(s.httpServer, ln)

	return &StartHTTPResponse{HTTPAddr: s.httpAddr}, nil
}

func (s *namespaceHTTPService) StopHTTP() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.httpServer == nil {
		return nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	err := s.httpServer.Shutdown(ctx)
	s.httpServer = nil
	s.httpAddr = ""
	s.port = 0
	return err
}

func (s *namespaceHTTPService) Status() (*StatusResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	return &StatusResponse{
		Namespace:   s.cfg.Namespace,
		Interface:   s.cfg.Interface,
		IPCIDR:      s.cfg.IPCIDR,
		MAC:         s.cfg.MAC,
		Gateway:     s.cfg.Gateway,
		OpenPort:    s.cfg.OpenPort,
		AllowICMP:   s.cfg.AllowICMP,
		HTTPAddr:    s.httpAddr,
		HTTPRunning: s.httpServer != nil,
	}, nil
}

type runningPlugin struct {
	cfg     NSConfig
	client  *plugin.Client
	rpc     NamespaceService
	pid     int
	sandbox pluginSandboxSpec
	cgroup  pluginCgroup
}

type namespaceCmdRunner struct {
	logger    hclog.Logger
	cmd       *exec.Cmd
	namespace string
	sandbox   pluginSandboxSpec
	cgroup    pluginCgroup

	stdout io.ReadCloser
	stderr io.ReadCloser
	path   string
	pid    int
}

func stagePluginChildBinary(selfBinary, runtimeDir string) (string, error) {
	// The child enters a new user namespace before exec, so it can lose DAC
	// bypass on private host paths like /home/$USER. Stage a private executable
	// copy under the runtime dir so the sandboxed child can always traverse and exec it.
	srcInfo, err := os.Stat(selfBinary)
	if err != nil {
		return "", fmt.Errorf("stat plugin child binary %q: %w", selfBinary, err)
	}

	staged := filepath.Join(runtimeDir, "plugin-child")
	if info, err := os.Stat(staged); err == nil {
		if info.Size() == srcInfo.Size() && info.Mode().Perm()&0o111 != 0 {
			return staged, nil
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return "", fmt.Errorf("stat staged plugin child %q: %w", staged, err)
	}

	src, err := os.Open(selfBinary)
	if err != nil {
		return "", fmt.Errorf("open plugin child binary %q: %w", selfBinary, err)
	}
	defer src.Close()

	tmp := staged + ".tmp"
	dst, err := os.OpenFile(tmp, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, srcInfo.Mode().Perm()|0o111)
	if err != nil {
		return "", fmt.Errorf("create staged plugin child %q: %w", tmp, err)
	}

	copyErr := func() error {
		if _, err := io.Copy(dst, src); err != nil {
			return fmt.Errorf("copy plugin child binary to %q: %w", tmp, err)
		}
		if err := dst.Chmod(srcInfo.Mode().Perm() | 0o111); err != nil {
			return fmt.Errorf("chmod staged plugin child %q: %w", tmp, err)
		}
		if err := dst.Close(); err != nil {
			return fmt.Errorf("close staged plugin child %q: %w", tmp, err)
		}
		if err := os.Rename(tmp, staged); err != nil {
			return fmt.Errorf("rename staged plugin child to %q: %w", staged, err)
		}
		return nil
	}()
	if copyErr != nil {
		_ = dst.Close()
		_ = os.Remove(tmp)
		return "", copyErr
	}

	return staged, nil
}

func newNamespaceCmdRunner(logger hclog.Logger, cmd *exec.Cmd, namespace string, sandbox pluginSandboxSpec) (*namespaceCmdRunner, error) {
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}

	stderr, err := cmd.StderrPipe()
	if err != nil {
		return nil, err
	}

	if err := applyPluginSandboxSysProcAttr(cmd); err != nil {
		return nil, err
	}

	cgroup, err := pluginCgroupFactory(namespace)
	if err != nil {
		return nil, err
	}

	displayPath := cmd.Path
	if len(cmd.Args) > 0 && cmd.Args[0] != "" {
		displayPath = cmd.Args[0]
	}

	return &namespaceCmdRunner{
		logger:    logger,
		cmd:       cmd,
		namespace: namespace,
		sandbox:   sandbox,
		cgroup:    cgroup,
		stdout:    stdout,
		stderr:    stderr,
		path:      displayPath,
	}, nil
}

func (r *namespaceCmdRunner) Start(_ context.Context) error {
	cgroupPath := ""
	if r.cgroup != nil {
		cgroupPath = r.cgroup.Path()
	}
	r.logger.Debug("starting plugin", "path", r.cmd.Path, "args", r.cmd.Args, "namespace", r.namespace, "sandbox_root", r.sandbox.rootDir, "cgroup", cgroupPath)
	if err := startCmdInNamedNamespace(r.cmd, r.namespace); err != nil {
		cleanupPluginCgroup(r.cgroup)
		return err
	}

	r.pid = r.cmd.Process.Pid
	if err := r.attachToCgroup(); err != nil {
		return err
	}
	r.logger.Debug("plugin started", "path", r.path, "pid", r.pid, "namespace", r.namespace, "cgroup", cgroupPath)
	return nil
}

func (r *namespaceCmdRunner) attachToCgroup() error {
	if r.cgroup == nil || r.cmd == nil || r.cmd.Process == nil {
		return nil
	}

	pid := uint64(r.cmd.Process.Pid)
	if err := r.cgroup.AddProc(pid); err != nil {
		_ = r.cmd.Process.Kill()
		_ = r.cmd.Wait()
		cleanupPluginCgroup(r.cgroup)
		return fmt.Errorf("add plugin pid %d to cgroup %q: %w", pid, r.cgroup.Path(), err)
	}
	return nil
}

func (r *namespaceCmdRunner) Wait(_ context.Context) error {
	return r.cmd.Wait()
}

func (r *namespaceCmdRunner) Kill(_ context.Context) error {
	if r.cmd.Process == nil {
		return nil
	}

	err := r.cmd.Process.Kill()
	if errors.Is(err, os.ErrProcessDone) {
		return nil
	}
	return err
}

func (r *namespaceCmdRunner) Stdout() io.ReadCloser {
	return r.stdout
}

func (r *namespaceCmdRunner) Stderr() io.ReadCloser {
	return r.stderr
}

func (r *namespaceCmdRunner) Name() string {
	return r.path
}

func (r *namespaceCmdRunner) ID() string {
	return fmt.Sprintf("%d", r.pid)
}

func (r *namespaceCmdRunner) Diagnose(_ context.Context) string {
	return fmt.Sprintf("failed to start %s in network namespace %q", r.path, r.namespace)
}

func (r *namespaceCmdRunner) PluginToHost(pluginNet, pluginAddr string) (string, string, error) {
	return r.sandbox.pluginToHostAddr(pluginNet, pluginAddr)
}

func (r *namespaceCmdRunner) HostToPlugin(hostNet, hostAddr string) (string, string, error) {
	return r.sandbox.hostToPluginAddr(hostNet, hostAddr)
}

var _ runner.Runner = (*namespaceCmdRunner)(nil)

func (p *runningPlugin) Stop() {
	if p == nil {
		return
	}
	if p.rpc != nil {
		_ = p.rpc.StopHTTP()
	}
	if p.client != nil {
		p.client.Kill()
		p.client = nil
	}
	if p.cgroup != nil {
		cleanupPluginCgroup(p.cgroup)
		p.cgroup = nil
	}
}

func startCmdInNamedNamespace(cmd *exec.Cmd, namespace string) (err error) {
	ns, err := netns.GetFromName(namespace)
	if err != nil {
		return fmt.Errorf("lookup namespace %q: %w", namespace, err)
	}
	defer ns.Close()

	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	original, err := netns.Get()
	if err != nil {
		return fmt.Errorf("get current namespace: %w", err)
	}
	defer original.Close()

	if err := netns.Set(ns); err != nil {
		return fmt.Errorf("enter namespace %q: %w", namespace, err)
	}

	started := false
	defer func() {
		restoreErr := netns.Set(original)
		if restoreErr == nil {
			return
		}
		if started && cmd.Process != nil {
			_ = cmd.Process.Kill()
			_ = cmd.Wait()
		}
		if err == nil {
			err = fmt.Errorf("restore original namespace after starting %q: %w", namespace, restoreErr)
		}
	}()

	if err := cmd.Start(); err != nil {
		return err
	}
	started = true

	return nil
}

func envDefault(key, fallback string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return fallback
}

func normalizeNSConfig(cfg NSConfig) NSConfig {
	if cfg.OpenPort == 0 {
		cfg.OpenPort = cfg.ListenPort
	}
	return cfg
}

func nftablesInterfaceName(name string) []byte {
	data := make([]byte, 16)
	copy(data, []byte(name+"\x00"))
	return data
}

func defaultConfigs(parentNIC string) []NSConfig {
	return []NSConfig{
		{
			Name:       "ns1",
			VLANID:     1,
			IfName:     parentNIC + ".1",
			IPCIDR:     "192.168.1.10/24",
			MAC:        "02:00:00:00:01:01",
			Gateway:    "192.168.1.1",
			ListenPort: 8080,
			OpenPort:   8080,
			AllowICMP:  false,
		},
		{
			Name:       "ns2",
			VLANID:     2,
			IfName:     parentNIC + ".2",
			IPCIDR:     "192.168.2.10/24",
			MAC:        "02:00:00:00:02:02",
			Gateway:    "192.168.2.1",
			ListenPort: 8080,
			OpenPort:   8080,
			AllowICMP:  true,
		},
	}
}

func loadConfigs(parentNIC string) ([]NSConfig, error) {
	raw := os.Getenv("NS_CONFIG_JSON")
	if raw == "" {
		return defaultConfigs(parentNIC), nil
	}

	var cfgs []NSConfig
	if err := json.Unmarshal([]byte(raw), &cfgs); err != nil {
		return nil, fmt.Errorf("parse NS_CONFIG_JSON: %w", err)
	}
	if len(cfgs) == 0 {
		return nil, errors.New("NS_CONFIG_JSON did not contain any namespace configs")
	}
	for i := range cfgs {
		cfgs[i] = normalizeNSConfig(cfgs[i])
	}
	return cfgs, nil
}

func pluginConfigJSON(cfg NSConfig) (string, error) {
	cfg = normalizeNSConfig(cfg)

	raw, err := json.Marshal(PluginConfig{
		Namespace: cfg.Name,
		Interface: cfg.IfName,
		IPCIDR:    cfg.IPCIDR,
		MAC:       cfg.MAC,
		Gateway:   cfg.Gateway,
		OpenPort:  cfg.OpenPort,
		AllowICMP: cfg.AllowICMP,
	})
	if err != nil {
		return "", err
	}
	return string(raw), nil
}

func loadPluginConfigFromEnv() (PluginConfig, error) {
	raw := os.Getenv("NS_PLUGIN_CONFIG")
	if raw == "" {
		return PluginConfig{}, errors.New("NS_PLUGIN_CONFIG is not set")
	}

	var cfg PluginConfig
	if err := json.Unmarshal([]byte(raw), &cfg); err != nil {
		return PluginConfig{}, fmt.Errorf("parse NS_PLUGIN_CONFIG: %w", err)
	}
	return cfg, nil
}

func validateHostConfig(parentNIC string, configs []NSConfig) error {
	if _, err := hostLinkByName(parentNIC); err != nil {
		return fmt.Errorf("lookup parent link %q: %w", parentNIC, err)
	}

	seenNamespaces := make(map[string]struct{}, len(configs))
	seenInterfaces := make(map[string]struct{}, len(configs))
	for _, rawCfg := range configs {
		cfg := normalizeNSConfig(rawCfg)

		if cfg.Name == "" {
			return errors.New("namespace name must not be empty")
		}
		if cfg.IfName == "" {
			return fmt.Errorf("interface name must not be empty for namespace %q", cfg.Name)
		}
		if _, ok := seenNamespaces[cfg.Name]; ok {
			return fmt.Errorf("duplicate namespace name %q", cfg.Name)
		}
		seenNamespaces[cfg.Name] = struct{}{}
		if _, ok := seenInterfaces[cfg.IfName]; ok {
			return fmt.Errorf("duplicate interface name %q", cfg.IfName)
		}
		seenInterfaces[cfg.IfName] = struct{}{}

		if _, err := netlink.ParseAddr(cfg.IPCIDR); err != nil {
			return fmt.Errorf("parse ip %q for namespace %q: %w", cfg.IPCIDR, cfg.Name, err)
		}
		if cfg.MAC != "" {
			if _, err := net.ParseMAC(cfg.MAC); err != nil {
				return fmt.Errorf("parse mac %q for namespace %q: %w", cfg.MAC, cfg.Name, err)
			}
		}
		if cfg.Gateway != "" && net.ParseIP(cfg.Gateway) == nil {
			return fmt.Errorf("invalid gateway %q for namespace %q", cfg.Gateway, cfg.Name)
		}
		if cfg.OpenPort < 0 || cfg.OpenPort > 65535 {
			return fmt.Errorf("invalid open port %d for namespace %q", cfg.OpenPort, cfg.Name)
		}
	}

	return nil
}

func listNamedNamespaces() ([]string, error) {
	entries, err := readDirEntries(namedNetnsDir)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, fmt.Errorf("read named namespaces from %q: %w", namedNetnsDir, err)
	}

	names := make([]string, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		names = append(names, entry.Name())
	}
	sort.Strings(names)
	return names, nil
}

func listRuntimeNamespaces(runtimeBase string) ([]string, error) {
	entries, err := readDirEntries(runtimeBase)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, fmt.Errorf("read runtime base %q: %w", runtimeBase, err)
	}

	names := make([]string, 0, len(entries))
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		names = append(names, entry.Name())
	}
	sort.Strings(names)
	return names, nil
}

func destroyNamespaceLinksInNetns(name string) error {
	ns, err := netns.GetFromName(name)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return fmt.Errorf("lookup namespace %q: %w", name, err)
	}
	defer ns.Close()

	handle, err := netlink.NewHandleAt(ns)
	if err != nil {
		return fmt.Errorf("open netlink handle in %q: %w", name, err)
	}
	defer handle.Delete()

	links, err := handle.LinkList()
	if err != nil {
		return fmt.Errorf("list links in %q: %w", name, err)
	}
	for _, link := range links {
		if link.Attrs() == nil || link.Attrs().Name == "lo" {
			continue
		}
		if err := handle.LinkDel(link); err != nil {
			return fmt.Errorf("delete link %q in %q: %w", link.Attrs().Name, name, err)
		}
	}

	return nil
}

func destroyNamespaceState(name, runtimeBase string) error {
	if name == "" {
		return nil
	}

	if err := destroyNamespaceLinks(name); err != nil {
		return err
	}
	if err := deleteNamedNamespace(name); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("delete namespace %q: %w", name, err)
	}
	if runtimeBase == "" {
		return nil
	}
	if err := removeAllPath(filepath.Join(runtimeBase, name)); err != nil {
		return fmt.Errorf("remove runtime dir for %q: %w", name, err)
	}
	return nil
}

func cleanupNamespaceSet(runtimeBase string, names []string) {
	for _, name := range uniqueSortedStrings(names) {
		if err := destroyNamespaceState(name, runtimeBase); err != nil {
			log.Printf("cleanup namespace=%s failed: %v", name, err)
		}
	}
}

func uniqueSortedStrings(values []string) []string {
	if len(values) == 0 {
		return nil
	}

	seen := make(map[string]struct{}, len(values))
	out := make([]string, 0, len(values))
	for _, value := range values {
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	sort.Strings(out)
	return out
}

func reconcileNamespaces(parentNIC, runtimeBase string, configs []NSConfig) ([]string, error) {
	if err := validateHostConfig(parentNIC, configs); err != nil {
		return nil, err
	}

	namespaces, err := listNamedNamespaces()
	if err != nil {
		return nil, err
	}
	runtimeNamespaces, err := listRuntimeNamespaces(runtimeBase)
	if err != nil {
		return nil, err
	}

	cleanupNames := make([]string, 0, len(namespaces)+len(runtimeNamespaces)+len(configs))
	cleanupNames = append(cleanupNames, namespaces...)
	cleanupNames = append(cleanupNames, runtimeNamespaces...)
	for _, cfg := range configs {
		cleanupNames = append(cleanupNames, cfg.Name)
	}
	cleanupNames = uniqueSortedStrings(cleanupNames)

	for _, name := range cleanupNames {
		if err := destroyNamespaceState(name, runtimeBase); err != nil {
			return nil, err
		}
	}

	recreated := make([]string, 0, len(configs))
	for _, cfg := range configs {
		ns, err := setupNamespaceNetwork(parentNIC, cfg)
		if err != nil {
			cleanupNamespaceSet(runtimeBase, append(recreated, cfg.Name))
			return nil, err
		}
		_ = ns.Close()
		recreated = append(recreated, cfg.Name)
	}

	return recreated, nil
}

func ensureNamedNamespace(name string) (netns.NsHandle, error) {
	if ns, err := netns.GetFromName(name); err == nil {
		return ns, nil
	}

	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	original, err := netns.Get()
	if err != nil {
		return netns.None(), err
	}
	defer original.Close()

	ns, err := netns.NewNamed(name)
	if err != nil {
		return netns.None(), err
	}

	if err := netns.Set(original); err != nil {
		ns.Close()
		return netns.None(), err
	}

	return ns, nil
}

func namespaceHasLink(ns netns.NsHandle, linkName string) (bool, error) {
	handle, err := netlink.NewHandleAt(ns)
	if err != nil {
		return false, err
	}
	defer handle.Delete()

	links, err := handle.LinkList()
	if err != nil {
		return false, err
	}
	for _, link := range links {
		if link.Attrs().Name == linkName {
			return true, nil
		}
	}
	return false, nil
}

func ensureVLANInHost(parentName, ifName string, vlanID int) error {
	parent, err := netlink.LinkByName(parentName)
	if err != nil {
		return fmt.Errorf("lookup parent link %q: %w", parentName, err)
	}

	existing, err := netlink.LinkByName(ifName)
	if err == nil {
		vlan, ok := existing.(*netlink.Vlan)
		if !ok {
			return fmt.Errorf("existing link %q is %T, want *netlink.Vlan", ifName, existing)
		}
		if vlan.VlanId != vlanID {
			return fmt.Errorf("existing vlan %q has vlan id %d, want %d", ifName, vlan.VlanId, vlanID)
		}
		if existing.Attrs().ParentIndex != parent.Attrs().Index {
			return fmt.Errorf("existing vlan %q has parent index %d, want %d", ifName, existing.Attrs().ParentIndex, parent.Attrs().Index)
		}
		return nil
	}

	attrs := netlink.NewLinkAttrs()
	attrs.Name = ifName
	attrs.ParentIndex = parent.Attrs().Index

	vlan := &netlink.Vlan{LinkAttrs: attrs, VlanId: vlanID}
	if err := netlink.LinkAdd(vlan); err != nil {
		return fmt.Errorf("add vlan link %q: %w", ifName, err)
	}
	return nil
}

func moveLinkToNamespace(ifName string, ns netns.NsHandle) error {
	link, err := netlink.LinkByName(ifName)
	if err != nil {
		return fmt.Errorf("lookup link %q in host namespace: %w", ifName, err)
	}
	if err := netlink.LinkSetNsFd(link, int(ns)); err != nil {
		return fmt.Errorf("move link %q to namespace: %w", ifName, err)
	}
	return nil
}

func configureLinkInNamespace(ns netns.NsHandle, cfg NSConfig) error {
	handle, err := netlink.NewHandleAt(ns)
	if err != nil {
		return err
	}
	defer handle.Delete()

	lo, err := handle.LinkByName("lo")
	if err != nil {
		return err
	}
	if err := handle.LinkSetUp(lo); err != nil {
		return fmt.Errorf("bring lo up in %s: %w", cfg.Name, err)
	}

	link, err := handle.LinkByName(cfg.IfName)
	if err != nil {
		return fmt.Errorf("lookup %q in %s: %w", cfg.IfName, cfg.Name, err)
	}

	if cfg.MAC != "" {
		wantMAC, err := net.ParseMAC(cfg.MAC)
		if err != nil {
			return fmt.Errorf("parse mac %q: %w", cfg.MAC, err)
		}
		currentMAC := link.Attrs().HardwareAddr
		if currentMAC == nil || currentMAC.String() != wantMAC.String() {
			if err := handle.LinkSetDown(link); err != nil {
				return fmt.Errorf("set %q down before mac change: %w", cfg.IfName, err)
			}
			if err := handle.LinkSetHardwareAddr(link, wantMAC); err != nil {
				return fmt.Errorf("set mac on %q: %w", cfg.IfName, err)
			}
			link, err = handle.LinkByName(cfg.IfName)
			if err != nil {
				return fmt.Errorf("re-lookup %q after mac change: %w", cfg.IfName, err)
			}
		}
	}

	addr, err := netlink.ParseAddr(cfg.IPCIDR)
	if err != nil {
		return fmt.Errorf("parse ip %q: %w", cfg.IPCIDR, err)
	}
	addrs, err := handle.AddrList(link, netlink.FAMILY_ALL)
	if err != nil {
		return fmt.Errorf("list addresses on %q: %w", cfg.IfName, err)
	}
	for _, existing := range addrs {
		if existing.Equal(*addr) {
			continue
		}
		stale := existing
		if err := handle.AddrDel(link, &stale); err != nil {
			return fmt.Errorf("delete stale address %s on %q: %w", stale.String(), cfg.IfName, err)
		}
	}
	if err := handle.AddrReplace(link, addr); err != nil {
		return fmt.Errorf("set address %s on %q: %w", cfg.IPCIDR, cfg.IfName, err)
	}

	if err := handle.LinkSetUp(link); err != nil {
		return fmt.Errorf("bring %q up: %w", cfg.IfName, err)
	}

	routes, err := handle.RouteList(link, netlink.FAMILY_ALL)
	if err != nil {
		return fmt.Errorf("list routes on %q: %w", cfg.IfName, err)
	}
	for _, route := range routes {
		if route.Dst != nil {
			continue
		}
		stale := route
		if err := handle.RouteDel(&stale); err != nil {
			return fmt.Errorf("delete stale default route on %q: %w", cfg.IfName, err)
		}
	}
	if cfg.Gateway != "" {
		gateway := net.ParseIP(cfg.Gateway)
		if gateway == nil {
			return fmt.Errorf("invalid gateway %q", cfg.Gateway)
		}
		if err := handle.RouteReplace(&netlink.Route{LinkIndex: link.Attrs().Index, Gw: gateway}); err != nil {
			return fmt.Errorf("set default route via %s on %q: %w", gateway, cfg.IfName, err)
		}
	}

	return nil
}

func setupNamespaceNetwork(parentNIC string, cfg NSConfig) (netns.NsHandle, error) {
	cfg = normalizeNSConfig(cfg)

	ns, err := ensureNamedNamespace(cfg.Name)
	if err != nil {
		return netns.None(), err
	}

	if err := ensureVLANInHost(parentNIC, cfg.IfName, cfg.VLANID); err != nil {
		ns.Close()
		return netns.None(), err
	}
	if err := moveLinkToNamespace(cfg.IfName, ns); err != nil {
		ns.Close()
		return netns.None(), err
	}

	if err := configureLinkInNamespace(ns, cfg); err != nil {
		ns.Close()
		return netns.None(), err
	}
	if err := configureNamespaceFirewall(ns, cfg); err != nil {
		ns.Close()
		return netns.None(), err
	}

	return ns, nil
}

func startNamespacePlugin(selfBinary, runtimeBase string, cfg NSConfig) (*runningPlugin, error) {
	cfg = normalizeNSConfig(cfg)

	runtimeDir := filepath.Join(runtimeBase, cfg.Name)
	if err := os.MkdirAll(runtimeDir, 0o755); err != nil {
		return nil, fmt.Errorf("create runtime dir %q: %w", runtimeDir, err)
	}

	childBinary, err := stagePluginChildBinary(selfBinary, runtimeDir)
	if err != nil {
		return nil, err
	}

	cfgJSON, err := pluginConfigJSON(cfg)
	if err != nil {
		return nil, err
	}

	var cmdRunner *namespaceCmdRunner
	client := plugin.NewClient(&plugin.ClientConfig{
		HandshakeConfig: handshake,
		Plugins:         pluginMap,
		RunnerFunc: func(logger hclog.Logger, cmd *exec.Cmd, socketDir string) (runner.Runner, error) {
			sandbox, err := newPluginSandboxSpec(runtimeDir, socketDir)
			if err != nil {
				return nil, err
			}
			cmd.Path = childBinary
			cmd.Args = []string{selfBinary}
			cmd.Env = append(cmd.Env,
				"NS_PLUGIN_MODE=1",
				"NS_PLUGIN_CONFIG="+cfgJSON,
			)
			cmd.Env = append(cmd.Env, sandbox.env()...)
			cmdRunner, err = newNamespaceCmdRunner(logger, cmd, cfg.Name, sandbox)
			if err != nil {
				return nil, err
			}
			return cmdRunner, nil
		},
		AllowedProtocols: []plugin.Protocol{
			plugin.ProtocolNetRPC,
		},
		StartTimeout: 20 * time.Second,
		UnixSocketConfig: &plugin.UnixSocketConfig{
			TempDir: runtimeDir,
		},
		SyncStdout: os.Stdout,
		SyncStderr: os.Stderr,
		Stderr:     os.Stderr,
	})

	rpcClient, err := client.Client()
	if err != nil {
		client.Kill()
		if cmdRunner != nil {
			cleanupPluginCgroup(cmdRunner.cgroup)
		}
		return nil, fmt.Errorf("connect plugin for %s: %w", cfg.Name, err)
	}

	raw, err := rpcClient.Dispense(pluginName)
	if err != nil {
		client.Kill()
		if cmdRunner != nil {
			cleanupPluginCgroup(cmdRunner.cgroup)
		}
		return nil, fmt.Errorf("dispense plugin for %s: %w", cfg.Name, err)
	}

	svc, ok := raw.(NamespaceService)
	if !ok {
		client.Kill()
		if cmdRunner != nil {
			cleanupPluginCgroup(cmdRunner.cgroup)
		}
		return nil, fmt.Errorf("dispensed plugin has type %T, want NamespaceService", raw)
	}

	if _, err := svc.StartHTTP(cfg.ListenPort); err != nil {
		client.Kill()
		if cmdRunner != nil {
			cleanupPluginCgroup(cmdRunner.cgroup)
		}
		return nil, fmt.Errorf("start namespace http server in %s: %w", cfg.Name, err)
	}

	rp := &runningPlugin{cfg: cfg, client: client, rpc: svc}
	if cmdRunner != nil {
		rp.pid = cmdRunner.pid
		rp.sandbox = cmdRunner.sandbox
		rp.cgroup = cmdRunner.cgroup
	}
	return rp, nil
}

func runHost(ctx context.Context, parentNIC, selfBinary, runtimeBase, hostHTTPAddr string, configs []NSConfig) (err error) {
	for i := range configs {
		configs[i] = normalizeNSConfig(configs[i])
	}
	if err := validateHostConfig(parentNIC, configs); err != nil {
		return err
	}

	recreatedNamespaces, err := reconcileNamespaces(parentNIC, runtimeBase, configs)
	if err != nil {
		return err
	}

	plugins := make([]*runningPlugin, 0, len(configs))
	cleanupNamespacesOnExit := true
	defer func() {
		for _, p := range plugins {
			p.Stop()
		}
		if cleanupNamespacesOnExit {
			cleanupNamespaceSet(runtimeBase, recreatedNamespaces)
		}
	}()

	for _, cfg := range configs {
		rp, err := startNamespacePlugin(selfBinary, runtimeBase, cfg)
		if err != nil {
			return err
		}
		plugins = append(plugins, rp)

		desc, err := rp.rpc.Describe()
		if err != nil {
			return err
		}
		status, err := rp.rpc.Status()
		if err != nil {
			return err
		}
		log.Printf("namespace=%s message=%q http=%s running=%v", desc.Namespace, desc.Message, status.HTTPAddr, status.HTTPRunning)
	}

	server, actualAddr, err := startHostDashboard(hostHTTPAddr, parentNIC, runtimeBase, plugins)
	if err != nil {
		return fmt.Errorf("start host dashboard on %s: %w", hostHTTPAddr, err)
	}
	log.Printf("host dashboard listening on http://%s", actualAddr)
	cleanupNamespacesOnExit = false

	<-ctx.Done()

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return server.Shutdown(shutdownCtx)
}

func runPluginMode() error {
	if err := ensurePluginSandbox(); err != nil {
		return err
	}

	cfg, err := loadPluginConfigFromEnv()
	if err != nil {
		return err
	}

	svc := &namespaceHTTPService{cfg: cfg}
	plugin.Serve(&plugin.ServeConfig{
		HandshakeConfig: handshake,
		Plugins: map[string]plugin.Plugin{
			pluginName: &namespaceServicePlugin{Impl: svc},
		},
	})
	return nil
}

func runMain() error {
	if os.Getenv(envPluginSandboxSeccompProbe) == "1" {
		return runPluginSandboxSeccompProbe()
	}

	if os.Getenv("NS_PLUGIN_MODE") == "1" {
		return runPluginMode()
	}

	if os.Geteuid() != 0 {
		return errors.New("run as root")
	}

	selfBinary, err := os.Executable()
	if err != nil {
		return err
	}

	parentNIC := envDefault("PARENT_NIC", "enp0s31f6")
	runtimeBase := envDefault("PLUGIN_RUNTIME_BASE", filepath.Join(os.TempDir(), "netforge"))
	hostHTTPAddr := envDefault("HOST_HTTP_ADDR", "127.0.0.1:8090")

	configs, err := loadConfigs(parentNIC)
	if err != nil {
		return err
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	return runHost(ctx, parentNIC, selfBinary, runtimeBase, hostHTTPAddr, configs)
}

func main() {
	if err := runMain(); err != nil {
		log.Fatal(err)
	}
}
