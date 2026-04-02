package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/rpc"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"sync"
	"syscall"
	"time"

	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/go-plugin"
	"github.com/hashicorp/go-plugin/runner"
	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netns"
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
}

type PluginConfig struct {
	Namespace string `json:"namespace"`
	Interface string `json:"interface"`
	IPCIDR    string `json:"ip_cidr"`
	MAC       string `json:"mac"`
	Gateway   string `json:"gateway"`
}

type HandshakeResponse struct {
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
	HTTPAddr    string
	HTTPRunning bool
}

type NamespaceService interface {
	Handshake() (*HandshakeResponse, error)
	StartHTTP(port int) (*StartHTTPResponse, error)
	StopHTTP() error
	Status() (*StatusResponse, error)
}

var handshake = plugin.HandshakeConfig{
	ProtocolVersion:  1,
	MagicCookieKey:   "NS_PLUGIN",
	MagicCookieValue: "namespace-service",
}

type nsPlugin struct {
	Impl NamespaceService
}

func (p *nsPlugin) Server(*plugin.MuxBroker) (interface{}, error) {
	return &rpcServer{Impl: p.Impl}, nil
}

func (p *nsPlugin) Client(_ *plugin.MuxBroker, c *rpc.Client) (interface{}, error) {
	return &rpcClient{client: c}, nil
}

var pluginMap = map[string]plugin.Plugin{
	pluginName: &nsPlugin{},
}

type rpcServer struct {
	Impl NamespaceService
}

func (s *rpcServer) Handshake(_ struct{}, resp *HandshakeResponse) error {
	r, err := s.Impl.Handshake()
	if err != nil {
		return err
	}
	*resp = *r
	return nil
}

func (s *rpcServer) StartHTTP(port int, resp *StartHTTPResponse) error {
	r, err := s.Impl.StartHTTP(port)
	if err != nil {
		return err
	}
	*resp = *r
	return nil
}

func (s *rpcServer) StopHTTP(_ struct{}, _ *struct{}) error {
	return s.Impl.StopHTTP()
}

func (s *rpcServer) Status(_ struct{}, resp *StatusResponse) error {
	r, err := s.Impl.Status()
	if err != nil {
		return err
	}
	*resp = *r
	return nil
}

type rpcClient struct {
	client *rpc.Client
}

func (c *rpcClient) Handshake() (*HandshakeResponse, error) {
	var out HandshakeResponse
	err := c.client.Call("Plugin.Handshake", struct{}{}, &out)
	return &out, err
}

func (c *rpcClient) StartHTTP(port int) (*StartHTTPResponse, error) {
	var out StartHTTPResponse
	err := c.client.Call("Plugin.StartHTTP", port, &out)
	return &out, err
}

func (c *rpcClient) StopHTTP() error {
	var out struct{}
	return c.client.Call("Plugin.StopHTTP", struct{}{}, &out)
}

func (c *rpcClient) Status() (*StatusResponse, error) {
	var out StatusResponse
	err := c.client.Call("Plugin.Status", struct{}{}, &out)
	return &out, err
}

type service struct {
	cfg        PluginConfig
	mu         sync.Mutex
	httpServer *http.Server
	httpAddr   string
}

func (s *service) Handshake() (*HandshakeResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	return &HandshakeResponse{
		Namespace: s.cfg.Namespace,
		HTTPAddr:  s.httpAddr,
		Message:   "plugin ready",
	}, nil
}

func (s *service) StartHTTP(port int) (*StartHTTPResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.httpServer != nil {
		return &StartHTTPResponse{HTTPAddr: s.httpAddr}, nil
	}

	addr := ":" + strconv.Itoa(port)
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
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
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
	s.httpAddr = addr

	go func() {
		err := s.httpServer.Serve(ln)
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Printf("http server error in %s: %v", s.cfg.Namespace, err)
		}
	}()

	return &StartHTTPResponse{HTTPAddr: s.httpAddr}, nil
}

func (s *service) StopHTTP() error {
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
	return err
}

func (s *service) Status() (*StatusResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	return &StatusResponse{
		Namespace:   s.cfg.Namespace,
		Interface:   s.cfg.Interface,
		IPCIDR:      s.cfg.IPCIDR,
		MAC:         s.cfg.MAC,
		Gateway:     s.cfg.Gateway,
		HTTPAddr:    s.httpAddr,
		HTTPRunning: s.httpServer != nil,
	}, nil
}

func runPluginMode() {
	raw := os.Getenv("NS_PLUGIN_CONFIG")
	if raw == "" {
		log.Fatal("NS_PLUGIN_CONFIG not set")
	}

	var cfg PluginConfig
	if err := json.Unmarshal([]byte(raw), &cfg); err != nil {
		log.Fatal(err)
	}

	svc := &service{cfg: cfg}

	plugin.Serve(&plugin.ServeConfig{
		HandshakeConfig: handshake,
		Plugins: map[string]plugin.Plugin{
			pluginName: &nsPlugin{Impl: svc},
		},
	})
}

type namespaceRunner struct {
	cmd    *exec.Cmd
	stdout io.ReadCloser
	stderr io.ReadCloser
}

func (r *namespaceRunner) Start(context.Context) error { return r.cmd.Start() }
func (r *namespaceRunner) Wait(context.Context) error  { return r.cmd.Wait() }
func (r *namespaceRunner) Name() string                { return filepath.Base(r.cmd.Path) }
func (r *namespaceRunner) Stdout() io.ReadCloser      { return r.stdout }
func (r *namespaceRunner) Stderr() io.ReadCloser      { return r.stderr }
func (r *namespaceRunner) Diagnose(context.Context) string {
	return fmt.Sprintf("command=%v", r.cmd.Args)
}
func (r *namespaceRunner) ID() string {
	if r.cmd.Process == nil {
		return ""
	}
	return strconv.Itoa(r.cmd.Process.Pid)
}
func (r *namespaceRunner) Kill(context.Context) error {
	if r.cmd.Process == nil {
		return nil
	}
	return r.cmd.Process.Kill()
}
func (r *namespaceRunner) PluginToHost(network, addr string) (string, string, error) {
	return network, addr, nil
}
func (r *namespaceRunner) HostToPlugin(network, addr string) (string, string, error) {
	return network, addr, nil
}

func newNamespaceRunner(nsName string, cmdSpec *exec.Cmd) (runner.Runner, error) {
	stdoutServer, stdoutClient, err := os.Pipe()
	if err != nil {
		return nil, err
	}
	stderrServer, stderrClient, err := os.Pipe()
	if err != nil {
		return nil, err
	}

	cmd := exec.Command(
		"/usr/sbin/ip",
		append([]string{"netns", "exec", nsName, cmdSpec.Path}, cmdSpec.Args[1:]...)...,
	)
	cmd.Env = append([]string{}, cmdSpec.Env...)
	cmd.Stdin = nil
	cmd.Stdout = stdoutClient
	cmd.Stderr = stderrClient

	return &namespaceRunner{
		cmd:    cmd,
		stdout: stdoutServer,
		stderr: stderrServer,
	}, nil
}

type pluginProc struct {
	cfg    NSConfig
	client *plugin.Client
	rpc    NamespaceService
}

func must(err error) {
	if err != nil {
		panic(err)
	}
}

func withNamespace[T any](ns netns.NsHandle, fn func() (T, error)) (T, error) {
	orig, err := netns.Get()
	if err != nil {
		var zero T
		return zero, err
	}
	defer orig.Close()

	if err := netns.Set(ns); err != nil {
		var zero T
		return zero, err
	}
	defer netns.Set(orig)

	return fn()
}

func ensureNamespace(name string) netns.NsHandle {
	ns, err := netns.GetFromName(name)
	if err == nil {
		return ns
	}

	orig, err := netns.Get()
	must(err)
	defer orig.Close()

	ns, err = netns.NewNamed(name)
	must(err)

	must(netns.Set(orig))
	return ns
}

func linkExistsInCurrentNS(name string) bool {
	_, err := netlink.LinkByName(name)
	return err == nil
}

func linkExistsInNamespace(ns netns.NsHandle, name string) bool {
	ok, err := withNamespace(ns, func() (bool, error) {
		_, err := netlink.LinkByName(name)
		if err != nil {
			return false, nil
		}
		return true, nil
	})
	if err != nil {
		return false
	}
	return ok
}

func ensureVLANInHost(parentName, ifName string, vlanID int) {
	if linkExistsInCurrentNS(ifName) {
		return
	}

	parent, err := netlink.LinkByName(parentName)
	must(err)

	vlan := &netlink.Vlan{
		LinkAttrs: netlink.LinkAttrs{
			Name:        ifName,
			ParentIndex: parent.Attrs().Index,
		},
		VlanId: vlanID,
	}
	err = netlink.LinkAdd(vlan)
	if err != nil && !os.IsExist(err) && !errors.Is(err, syscall.EEXIST) {
		panic(err)
	}
}

func ensureMACCurrentNS(ifName, mac string) {
	if mac == "" {
		return
	}

	link, err := netlink.LinkByName(ifName)
	must(err)

	want, err := net.ParseMAC(mac)
	must(err)

	cur := link.Attrs().HardwareAddr
	if cur != nil && cur.String() == want.String() {
		return
	}

	must(netlink.LinkSetHardwareAddr(link, want))
}

func moveLinkToNamespaceIfNeeded(ifName string, ns netns.NsHandle) {
	if linkExistsInNamespace(ns, ifName) {
		return
	}

	link, err := netlink.LinkByName(ifName)
	must(err)
	must(netlink.LinkSetNsFd(link, int(ns)))
}

func ensureAddrCurrentNS(link netlink.Link, ipCIDR string) {
	want, err := netlink.ParseAddr(ipCIDR)
	must(err)

	addrs, err := netlink.AddrList(link, netlink.FAMILY_ALL)
	must(err)

	for _, a := range addrs {
		if a.IPNet != nil && want.IPNet != nil &&
			a.IPNet.IP.Equal(want.IPNet.IP) &&
			maskEqual(a.IPNet.Mask, want.IPNet.Mask) {
			return
		}
	}

	err = netlink.AddrAdd(link, want)
	if err != nil && !os.IsExist(err) && !errors.Is(err, syscall.EEXIST) {
		panic(err)
	}
}

func maskEqual(a, b net.IPMask) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func ensureDefaultRouteCurrentNS(link netlink.Link, gateway string) {
	if gateway == "" {
		return
	}

	gw := net.ParseIP(gateway)
	if gw == nil {
		panic(fmt.Errorf("invalid gateway %q", gateway))
	}

	routes, err := netlink.RouteList(link, netlink.FAMILY_V4)
	must(err)

	for _, r := range routes {
		if r.Dst == nil && r.Gw != nil && r.Gw.Equal(gw) {
			return
		}
	}

	err = netlink.RouteAdd(&netlink.Route{
		LinkIndex: link.Attrs().Index,
		Gw:        gw,
	})
	if err != nil && !os.IsExist(err) && !errors.Is(err, syscall.EEXIST) {
		panic(err)
	}
}

func configureLinkInNamespace(ns netns.NsHandle, ifName, ipCIDR, mac, gateway string) {
	_, err := withNamespace(ns, func() (struct{}, error) {
		lo, err := netlink.LinkByName("lo")
		if err != nil {
			return struct{}{}, err
		}
		if err := netlink.LinkSetUp(lo); err != nil {
			return struct{}{}, err
		}

		link, err := netlink.LinkByName(ifName)
		if err != nil {
			return struct{}{}, err
		}

		if mac != "" {
			want, err := net.ParseMAC(mac)
			if err != nil {
				return struct{}{}, err
			}
			cur := link.Attrs().HardwareAddr
			if cur == nil || cur.String() != want.String() {
				if err := netlink.LinkSetHardwareAddr(link, want); err != nil {
					return struct{}{}, err
				}
				link, err = netlink.LinkByName(ifName)
				if err != nil {
					return struct{}{}, err
				}
			}
		}

		ensureAddrCurrentNS(link, ipCIDR)

		if err := netlink.LinkSetUp(link); err != nil {
			return struct{}{}, err
		}

		ensureDefaultRouteCurrentNS(link, gateway)
		return struct{}{}, nil
	})
	must(err)
}

func pluginConfigJSON(cfg NSConfig) string {
	raw, err := json.Marshal(PluginConfig{
		Namespace: cfg.Name,
		Interface: cfg.IfName,
		IPCIDR:    cfg.IPCIDR,
		MAC:       cfg.MAC,
		Gateway:   cfg.Gateway,
	})
	must(err)
	return string(raw)
}

func startPlugin(selfBin string, runtimeBase string, cfg NSConfig) (*pluginProc, error) {
	runtimeDir := filepath.Join(runtimeBase, cfg.Name)
	if err := os.MkdirAll(runtimeDir, 0o770); err != nil {
		return nil, err
	}

	client := plugin.NewClient(&plugin.ClientConfig{
		HandshakeConfig: handshake,
		Plugins:         pluginMap,
		AllowedProtocols: []plugin.Protocol{
			plugin.ProtocolNetRPC,
		},
		StartTimeout: 20 * time.Second,
		UnixSocketConfig: &plugin.UnixSocketConfig{
			TempDir: runtimeDir,
		},
		RunnerFunc: func(_ hclog.Logger, cmd *exec.Cmd, _ string) (runner.Runner, error) {
			cmd.Path = selfBin
			cmd.Args = []string{selfBin}
			cmd.Env = append(
				os.Environ(),
				"NS_PLUGIN_MODE=1",
				"NS_PLUGIN_CONFIG="+pluginConfigJSON(cfg),
			)
			return newNamespaceRunner(cfg.Name, cmd)
		},
	})

	rpcClient, err := client.Client()
	if err != nil {
		client.Kill()
		return nil, err
	}

	raw, err := rpcClient.Dispense(pluginName)
	if err != nil {
		client.Kill()
		return nil, err
	}

	svc := raw.(NamespaceService)

	if _, err := svc.StartHTTP(cfg.ListenPort); err != nil {
		client.Kill()
		return nil, err
	}

	return &pluginProc{
		cfg:    cfg,
		client: client,
		rpc:    svc,
	}, nil
}

func runHostMode() {
	if os.Geteuid() != 0 {
		log.Fatal("run as root")
	}

	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	selfBin, err := os.Executable()
	must(err)

	parentNIC := envDefault("PARENT_NIC", "eth0")
	runtimeBase := envDefault("PLUGIN_RUNTIME_BASE", "/run/ns-go-plugin-demo")

	configs := []NSConfig{
		{
			Name:       "ns1",
			VLANID:     1,
			IfName:     "eth0.1",
			IPCIDR:     "192.168.1.10/24",
			MAC:        "02:00:00:00:01:01",
			Gateway:    "192.168.1.1",
			ListenPort: 8080,
		},
		{
			Name:       "ns2",
			VLANID:     2,
			IfName:     "eth0.2",
			IPCIDR:     "192.168.2.10/24",
			MAC:        "02:00:00:00:02:02",
			Gateway:    "192.168.2.1",
			ListenPort: 8080,
		},
	}

	procs := make([]*pluginProc, 0, len(configs))

	for _, cfg := range configs {
		ns := ensureNamespace(cfg.Name)
		defer ns.Close()

		if !linkExistsInNamespace(ns, cfg.IfName) {
			ensureVLANInHost(parentNIC, cfg.IfName, cfg.VLANID)
			ensureMACCurrentNS(cfg.IfName, cfg.MAC)
			moveLinkToNamespaceIfNeeded(cfg.IfName, ns)
		}

		configureLinkInNamespace(ns, cfg.IfName, cfg.IPCIDR, cfg.MAC, cfg.Gateway)

		proc, err := startPlugin(selfBin, runtimeBase, cfg)
		if err != nil {
			log.Fatalf("failed to start plugin for %s: %v", cfg.Name, err)
		}
		procs = append(procs, proc)

		hs, err := proc.rpc.Handshake()
		must(err)

		st, err := proc.rpc.Status()
		must(err)

		log.Printf(
			"plugin ready namespace=%s http=%s running=%v message=%s",
			hs.Namespace,
			st.HTTPAddr,
			st.HTTPRunning,
			hs.Message,
		)
	}

	log.Printf("started %d namespace plugins", len(procs))
	select {}
}

func envDefault(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func main() {
	if os.Getenv("NS_PLUGIN_MODE") == "1" {
		runPluginMode()
		return
	}
	runHostMode()
}
