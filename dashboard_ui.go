//go:build linux

package main

import "html/template"

const (
	hostDashboardPageOverview = "overview"
	hostDashboardPageProbes   = "probes"
	hostDashboardPageJobs     = "jobs"
	hostDashboardPageConfigs  = "configs"
)

func applyDashboardPageMetadata(data *hostDashboardData, page string) {
	switch page {
	case hostDashboardPageProbes:
		data.CurrentPage = hostDashboardPageProbes
		data.PageTitle = "NetForge Dashboard | Connectivity Probes"
		data.PageDescription = "Run ping, TCP reachability, and SFTP directory checks from individual namespaces."
	case hostDashboardPageJobs:
		data.CurrentPage = hostDashboardPageJobs
		data.PageTitle = "NetForge Dashboard | SFTP Sync Jobs"
		data.PageDescription = "Create and manage scheduled SFTP transfer jobs between namespaces."
	case hostDashboardPageConfigs:
		data.CurrentPage = hostDashboardPageConfigs
		data.PageTitle = "NetForge Dashboard | Configs"
		data.PageDescription = "Review the effective host and namespace configuration parameters in one place."
	default:
		data.CurrentPage = hostDashboardPageOverview
		data.PageTitle = "NetForge Dashboard | Namespace Overview"
		data.PageDescription = "Review namespace health, interface status, ARP visibility, and NIC statistics."
	}
}

func newHostDashboardTemplate() *template.Template {
	return template.Must(template.New("host-dashboard").Parse(`{{define "layout"}}<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{{.PageTitle}}</title>
<style>
:root {
	color-scheme: dark;
	--bg: #111827;
	--panel: #1f2937;
	--panel-alt: #0f172a;
	--border: #374151;
	--text: #e5e7eb;
	--muted: #9ca3af;
	--accent: #2563eb;
	--accent-hover: #1d4ed8;
	--success: #22c55e;
	--danger: #f87171;
}
body {
	font-family: "Segoe UI", sans-serif;
	margin: 0;
	background: var(--bg);
	color: var(--text);
}
.page-shell {
	max-width: 1400px;
	margin: 0 auto;
	padding: 2rem;
}
h1, h2 {
	margin-top: 0;
}
.headerbar {
	display: flex;
	flex-wrap: wrap;
	justify-content: space-between;
	align-items: flex-end;
	gap: 1rem;
	margin-bottom: 1.5rem;
}
.page-lede,
.section-copy {
	margin: 0.4rem 0 0;
	max-width: 62ch;
	color: var(--muted);
}
.site-nav {
	display: flex;
	flex-wrap: wrap;
	gap: 0.75rem;
}
.nav-link {
	display: inline-flex;
	align-items: center;
	justify-content: center;
	padding: 0.72rem 1.05rem;
	border-radius: 999px;
	border: 1px solid var(--border);
	background: var(--panel);
	color: var(--text);
	text-decoration: none;
	font-weight: 600;
}
.nav-link.active {
	background: var(--accent);
	border-color: var(--accent);
	color: #fff;
}
.meta {
	display: grid;
	grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
	gap: 1rem;
	margin: 1.5rem 0;
}
.section-stack {
	display: grid;
	gap: 1.5rem;
}
.card,
table {
	background: var(--panel);
	border: 1px solid var(--border);
	border-radius: 16px;
	box-shadow: 0 8px 24px rgba(0, 0, 0, 0.2);
}
.card {
	padding: 1rem 1.2rem;
}
.table-wrap {
	overflow-x: auto;
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
	border-bottom: 1px solid var(--border);
}
th {
	background: var(--panel-alt);
	color: var(--text);
	font-weight: 600;
}
tr:last-child td {
	border-bottom: 0;
}
.status-ok {
	color: var(--success);
	font-weight: 600;
}
.status-bad {
	color: var(--danger);
	font-weight: 600;
}
code {
	font-size: 0.95em;
	background: rgba(255, 255, 255, 0.05);
	border-radius: 4px;
	padding: 0.05rem 0.3rem;
}
form {
	margin: 0;
}
.probe-card {
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
.form-grid {
	display: grid;
	grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
	gap: 0.85rem;
	align-items: end;
}
.form-grid label {
	display: block;
	font-weight: 600;
}
.form-grid input,
.form-grid select,
.form-grid button {
	width: 100%;
	box-sizing: border-box;
	margin-top: 0.35rem;
	padding: 0.7rem 0.8rem;
	border-radius: 10px;
	border: 1px solid var(--border);
	background: var(--panel-alt);
	color: var(--text);
	font: inherit;
}
.form-grid button {
	background: var(--accent);
	color: #fff;
	cursor: pointer;
	font-weight: 600;
}
.form-grid button:hover {
	background: var(--accent-hover);
}
.control-stack {
	display: grid;
	gap: 0.6rem;
}
pre {
	margin: 0.85rem 0 0;
	padding: 0.9rem 1rem;
	background: #0b1220;
	color: var(--text);
	border-radius: 12px;
	overflow-x: auto;
	white-space: pre-wrap;
}
@media (max-width: 720px) {
	.page-shell {
		padding: 1.25rem;
	}
	.headerbar {
		align-items: flex-start;
	}
	.site-nav {
		width: 100%;
	}
}
</style>
</head>
<body>
<div class="page-shell">
<header class="headerbar">
<div>
<h1>NetForge Dashboard</h1>
<p class="page-lede">{{.PageDescription}}</p>
</div>
<nav class="site-nav" aria-label="Dashboard pages">
<a class="nav-link {{if eq .CurrentPage "overview"}}active{{end}}" href="/">Overview</a>
<a class="nav-link {{if eq .CurrentPage "probes"}}active{{end}}" href="/probes">Probes</a>
<a class="nav-link {{if eq .CurrentPage "jobs"}}active{{end}}" href="/sftp-jobs">SFTP Jobs</a>
<a class="nav-link {{if eq .CurrentPage "configs"}}active{{end}}" href="/configs">Configs</a>
</nav>
</header>
{{template "page-content" .}}
</div>
</body>
</html>{{end}}

{{define "page-content"}}{{if eq .CurrentPage "probes"}}{{template "probes" .}}{{else if eq .CurrentPage "jobs"}}{{template "jobs" .}}{{else if eq .CurrentPage "configs"}}{{template "configs" .}}{{else}}{{template "overview" .}}{{end}}{{end}}

{{define "overview"}}<div class="section-stack">
<div class="card">
<h2>Namespace Overview</h2>
<p class="section-copy">Each namespace has its own interface, firewall posture, and plugin process. This page keeps the infrastructure snapshot separate from the interactive tooling.</p>
</div>
<div class="table-wrap">
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
</div>
</div>{{end}}

{{define "configs"}}<div class="section-stack">
<div class="card">
<h2>Configs</h2>
<p class="section-copy">This page shows the effective host parameters and the namespace configuration values the dashboard is currently using.</p>
</div>
<div class="card">
<h2>Host Parameters</h2>
<div class="table-wrap">
<table>
<thead>
<tr>
<th>Parameter</th>
<th>Value</th>
<th>Description</th>
</tr>
</thead>
<tbody>
<tr>
<td><code>HOST_HTTP_ADDR</code></td>
<td><code>{{.HostHTTPAddr}}</code></td>
<td>Dashboard bind address</td>
</tr>
<tr>
<td><code>PARENT_NIC</code></td>
<td><code>{{.ParentNIC}}</code></td>
<td>Parent interface used for VLAN subinterfaces</td>
</tr>
<tr>
<td><code>RUNTIME_BASE</code></td>
<td><code>{{.RuntimeBase}}</code></td>
<td>Runtime directory used by NetForge</td>
</tr>
</tbody>
</table>
</div>
</div>
<div class="card">
<h2>Namespace Parameters</h2>
<div class="table-wrap">
<table>
<thead>
<tr>
<th><code>name</code></th>
<th><code>vlan_id</code></th>
<th><code>if_name</code></th>
<th><code>ip_cidr</code></th>
<th><code>mac</code></th>
<th><code>gateway</code></th>
<th><code>listen_port</code></th>
<th><code>open_ports</code></th>
<th><code>allow_icmp</code></th>
</tr>
</thead>
<tbody>
{{range .Namespaces}}
<tr>
<td><code>{{.Name}}</code></td>
<td><code>{{.VLANID}}</code></td>
<td><code>{{.Interface}}</code></td>
<td><code>{{.IPCIDR}}</code></td>
<td><code>{{.MAC}}</code></td>
<td><code>{{if .Gateway}}{{.Gateway}}{{else}}none{{end}}</code></td>
<td><code>{{.ListenPort}}</code></td>
<td><code>{{if .OpenPorts}}{{range $i, $port := .OpenPorts}}{{if $i}}, {{end}}{{$port}}{{end}}{{else}}none{{end}}</code></td>
<td><code>{{if .AllowICMP}}true{{else}}false{{end}}</code></td>
</tr>
{{end}}
</tbody>
</table>
</div>
</div>
</div>{{end}}

{{define "probes"}}<div class="section-stack">
<div class="card">
<h2>Connectivity Probes</h2>
<p class="section-copy">Operational checks live on their own page so you can troubleshoot connectivity without the namespace inventory competing for space.</p>
</div>
<div class="card probe-card">
<div class="probe-grid">
<div class="probe-pane">
<h2>Ping Target</h2>
<form class="form-grid" method="post" action="/ping">
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
<form class="form-grid" method="post" action="/tcp-check">
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
<div class="probe-pane">
<h2>SFTP File List</h2>
<form class="form-grid" method="post" action="/sftp-list">
<label>Namespace
<select name="namespace" required>
<option value="">Select namespace</option>
{{range .Namespaces}}
<option value="{{.Name}}" {{if eq $.SelectedSFTPNamespace .Name}}selected{{end}}>{{.Name}}</option>
{{end}}
</select>
</label>
<label>Server IP / Host
<input type="text" name="server_host" placeholder="192.168.1.10" value="{{.SFTPServerHost}}" required>
</label>
<label>TCP Port
<input type="number" name="port" min="1" max="65535" placeholder="22" value="{{.SFTPServerPort}}" required>
</label>
<label>User Name
<input type="text" name="username" placeholder="deploy" value="{{.SFTPUsername}}" required>
</label>
<label>Password
<input type="password" name="password" placeholder="password" required>
</label>
<label>Directory
<input type="text" name="directory" placeholder="." value="{{.SFTPDirectory}}">
</label>
<div>
<button type="submit">List SFTP Files</button>
</div>
</form>
{{if .SFTPListResult}}
<div style="margin-top: 1rem;">
{{if .SFTPListResult.Success}}
<div class="status-ok">SFTP list succeeded: <code>{{.SFTPListResult.Namespace}}</code> -> <code>{{.SFTPListResult.Server}}:{{.SFTPListResult.Port}}</code> as <code>{{.SFTPListResult.Username}}</code></div>
{{else}}
<div class="status-bad">SFTP list failed: <code>{{.SFTPListResult.Namespace}}</code> -> <code>{{.SFTPListResult.Server}}:{{.SFTPListResult.Port}}</code>{{if .SFTPListResult.Error}}<br>{{.SFTPListResult.Error}}{{end}}</div>
{{end}}
<div style="margin-top: 0.5rem;"><strong>Directory:</strong> <code>{{if .SFTPListResult.Directory}}{{.SFTPListResult.Directory}}{{else}}.{{end}}</code></div>
{{if .SFTPListResult.Entries}}
<div class="table-wrap" style="margin-top: 0.85rem;">
<table>
<thead>
<tr>
<th>Path</th>
<th>Type</th>
<th>Size</th>
<th>Mode</th>
</tr>
</thead>
<tbody>
{{range .SFTPListResult.Entries}}
<tr>
<td><code>{{.Path}}</code></td>
<td><code>{{if .IsDir}}dir{{else}}file{{end}}</code></td>
<td><code>{{.Size}}</code></td>
<td><code>{{printf "%#o" .Mode}}</code></td>
</tr>
{{end}}
</tbody>
</table>
</div>
{{else if .SFTPListResult.Success}}
<pre>empty directory</pre>
{{end}}
</div>
{{end}}
</div>
</div>
</div>
</div>{{end}}

{{define "jobs"}}<div class="section-stack">
<div class="card">
<h2>SFTP Sync Jobs</h2>
<p class="section-copy">Scheduled copy jobs are isolated on this page so operational automation is separate from one-off probe actions.</p>
</div>
<div class="card">
<form class="form-grid" method="post" action="/sftp-jobs/create">
<label>From Namespace
<select name="from_namespace" required>
<option value="">Select namespace</option>
{{range .Namespaces}}
<option value="{{.Name}}" {{if eq $.SFTPJobForm.FromNamespace .Name}}selected{{end}}>{{.Name}}</option>
{{end}}
</select>
</label>
<label>From Server IP / Host
<input type="text" name="from_host" placeholder="192.168.1.10" value="{{.SFTPJobForm.FromHost}}" required>
</label>
<label>From TCP Port
<input type="number" name="from_port" min="1" max="65535" placeholder="22" value="{{.SFTPJobForm.FromPort}}" required>
</label>
<label>From User Name
<input type="text" name="from_username" placeholder="source-user" value="{{.SFTPJobForm.FromUsername}}" required>
</label>
<label>From Password
<input type="password" name="from_password" placeholder="password" required>
</label>
<label>From Directory
<input type="text" name="from_directory" placeholder="/incoming" value="{{.SFTPJobForm.FromDirectory}}" required>
</label>
<label>To Namespace
<select name="to_namespace" required>
<option value="">Select namespace</option>
{{range .Namespaces}}
<option value="{{.Name}}" {{if eq $.SFTPJobForm.ToNamespace .Name}}selected{{end}}>{{.Name}}</option>
{{end}}
</select>
</label>
<label>To Server IP / Host
<input type="text" name="to_host" placeholder="192.168.1.20" value="{{.SFTPJobForm.ToHost}}" required>
</label>
<label>To TCP Port
<input type="number" name="to_port" min="1" max="65535" placeholder="22" value="{{.SFTPJobForm.ToPort}}" required>
</label>
<label>To User Name
<input type="text" name="to_username" placeholder="dest-user" value="{{.SFTPJobForm.ToUsername}}" required>
</label>
<label>To Password
<input type="password" name="to_password" placeholder="password" required>
</label>
<label>To Directory
<input type="text" name="to_directory" placeholder="/archive" value="{{.SFTPJobForm.ToDirectory}}" required>
</label>
<label>Run Interval
<input type="text" name="interval" placeholder="5m" value="{{.SFTPJobForm.Interval}}" required>
</label>
<div>
<button type="submit">Add SFTP Sync Job</button>
</div>
</form>
{{if .SFTPJobMessage}}
<div class="status-ok" style="margin-top: 1rem;">{{.SFTPJobMessage}}</div>
{{end}}
{{if .SFTPJobError}}
<div class="status-bad" style="margin-top: 1rem;">{{.SFTPJobError}}</div>
{{end}}
{{if .JobsError}}
<div class="status-bad" style="margin-top: 1rem;">{{.JobsError}}</div>
{{end}}
<div class="table-wrap" style="margin-top: 1rem;">
<table>
<thead>
<tr>
<th>ID</th>
<th>From</th>
<th>To</th>
<th>Interval</th>
<th>State</th>
<th>Last Result</th>
<th>Controls</th>
</tr>
</thead>
<tbody>
{{range .Jobs}}
<tr>
<td><code>{{.ID}}</code></td>
<td><code>{{.FromNamespace}}</code><br><code>{{.FromAddress}}</code><br><code>{{.FromUsername}}</code><br><code>{{.FromDirectory}}</code></td>
<td><code>{{.ToNamespace}}</code><br><code>{{.ToAddress}}</code><br><code>{{.ToUsername}}</code><br><code>{{.ToDirectory}}</code></td>
<td><code>{{.Interval}}</code></td>
<td>
{{if .Enabled}}
<span class="status-ok">enabled</span>
{{else}}
<span class="status-bad">disabled</span>
{{end}}
<br>
{{if .Running}}
<code>scheduler running</code>
{{else}}
<code>scheduler stopped</code>
{{end}}
</td>
<td>
<code>{{if .LastStatus}}{{.LastStatus}}{{else}}idle{{end}}</code><br>
<code>files copied {{.LastFilesCopied}}</code><br>
{{if .LastRunAt}}<code>last run {{.LastRunAt}}</code><br>{{end}}
{{if .LastSuccessAt}}<code>last success {{.LastSuccessAt}}</code><br>{{end}}
{{if .LastError}}<span class="status-bad">{{.LastError}}</span>{{end}}
</td>
<td>
<div class="control-stack">
{{if .Enabled}}
<form method="post" action="/sftp-jobs/stop">
<input type="hidden" name="job_id" value="{{.ID}}">
<button type="submit">Stop</button>
</form>
{{else}}
<form method="post" action="/sftp-jobs/start">
<input type="hidden" name="job_id" value="{{.ID}}">
<button type="submit">Start</button>
</form>
{{end}}
<form method="post" action="/sftp-jobs/delete">
<input type="hidden" name="job_id" value="{{.ID}}">
<button type="submit">Delete</button>
</form>
</div>
</td>
</tr>
{{else}}
<tr>
<td colspan="7"><code>no jobs configured</code></td>
</tr>
{{end}}
</tbody>
</table>
</div>
</div>
</div>{{end}}`))
}
