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
	"net/rpc"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"sync"
	"syscall"
	"time"

	"github.com/hashicorp/go-plugin"
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
		HTTPAddr:    s.httpAddr,
		HTTPRunning: s.httpServer != nil,
	}, nil
}

type runningPlugin struct {
	cfg    NSConfig
	client *plugin.Client
	rpc    NamespaceService
}

func (p *runningPlugin) Stop() {
	if p == nil {
		return
	}
	if p.rpc != nil {
		_ = p.rpc.StopHTTP()
	}
	if p.client != nil {
		p.client.Kill()
	}
}

func envDefault(key, fallback string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return fallback
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
		},
		{
			Name:       "ns2",
			VLANID:     2,
			IfName:     parentNIC + ".2",
			IPCIDR:     "192.168.2.10/24",
			MAC:        "02:00:00:00:02:02",
			Gateway:    "192.168.2.1",
			ListenPort: 8080,
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
	return cfgs, nil
}

func pluginConfigJSON(cfg NSConfig) (string, error) {
	raw, err := json.Marshal(PluginConfig{
		Namespace: cfg.Name,
		Interface: cfg.IfName,
		IPCIDR:    cfg.IPCIDR,
		MAC:       cfg.MAC,
		Gateway:   cfg.Gateway,
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
	if err := handle.AddrReplace(link, addr); err != nil {
		return fmt.Errorf("set address %s on %q: %w", cfg.IPCIDR, cfg.IfName, err)
	}

	if err := handle.LinkSetUp(link); err != nil {
		return fmt.Errorf("bring %q up: %w", cfg.IfName, err)
	}

	if cfg.Gateway != "" {
		gateway := net.ParseIP(cfg.Gateway)
		if gateway == nil {
			return fmt.Errorf("invalid gateway %q", cfg.Gateway)
		}

		routes, err := handle.RouteList(link, netlink.FAMILY_V4)
		if err != nil {
			return fmt.Errorf("list routes on %q: %w", cfg.IfName, err)
		}
		for _, route := range routes {
			if route.Dst == nil && route.Gw != nil && !route.Gw.Equal(gateway) {
				stale := route
				if err := handle.RouteDel(&stale); err != nil {
					return fmt.Errorf("delete stale default route via %s on %q: %w", stale.Gw, cfg.IfName, err)
				}
			}
		}

		if err := handle.RouteReplace(&netlink.Route{LinkIndex: link.Attrs().Index, Gw: gateway}); err != nil {
			return fmt.Errorf("set default route via %s on %q: %w", gateway, cfg.IfName, err)
		}
	}

	return nil
}

func setupNamespaceNetwork(parentNIC string, cfg NSConfig) (netns.NsHandle, error) {
	ns, err := ensureNamedNamespace(cfg.Name)
	if err != nil {
		return netns.None(), err
	}

	exists, err := namespaceHasLink(ns, cfg.IfName)
	if err != nil {
		ns.Close()
		return netns.None(), err
	}

	if !exists {
		if err := ensureVLANInHost(parentNIC, cfg.IfName, cfg.VLANID); err != nil {
			ns.Close()
			return netns.None(), err
		}
		if err := moveLinkToNamespace(cfg.IfName, ns); err != nil {
			ns.Close()
			return netns.None(), err
		}
	}

	if err := configureLinkInNamespace(ns, cfg); err != nil {
		ns.Close()
		return netns.None(), err
	}

	return ns, nil
}

func startNamespacePlugin(selfBinary, ipCmd, runtimeBase string, cfg NSConfig) (*runningPlugin, error) {
	runtimeDir := filepath.Join(runtimeBase, cfg.Name)
	if err := os.MkdirAll(runtimeDir, 0o755); err != nil {
		return nil, fmt.Errorf("create runtime dir %q: %w", runtimeDir, err)
	}

	cfgJSON, err := pluginConfigJSON(cfg)
	if err != nil {
		return nil, err
	}

	cmd := exec.Command(ipCmd, "netns", "exec", cfg.Name, selfBinary)
	cmd.Env = append(os.Environ(),
		"NS_PLUGIN_MODE=1",
		"NS_PLUGIN_CONFIG="+cfgJSON,
	)

	client := plugin.NewClient(&plugin.ClientConfig{
		HandshakeConfig: handshake,
		Plugins:         pluginMap,
		Cmd:             cmd,
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
		return nil, fmt.Errorf("connect plugin for %s: %w", cfg.Name, err)
	}

	raw, err := rpcClient.Dispense(pluginName)
	if err != nil {
		client.Kill()
		return nil, fmt.Errorf("dispense plugin for %s: %w", cfg.Name, err)
	}

	svc, ok := raw.(NamespaceService)
	if !ok {
		client.Kill()
		return nil, fmt.Errorf("dispensed plugin has type %T, want NamespaceService", raw)
	}

	if _, err := svc.StartHTTP(cfg.ListenPort); err != nil {
		client.Kill()
		return nil, fmt.Errorf("start namespace http server in %s: %w", cfg.Name, err)
	}

	return &runningPlugin{cfg: cfg, client: client, rpc: svc}, nil
}

func runHost(ctx context.Context, parentNIC, selfBinary, ipCmd, runtimeBase string, configs []NSConfig) error {
	plugins := make([]*runningPlugin, 0, len(configs))
	defer func() {
		for _, p := range plugins {
			p.Stop()
		}
	}()

	for _, cfg := range configs {
		ns, err := setupNamespaceNetwork(parentNIC, cfg)
		if err != nil {
			return err
		}
		_ = ns.Close()

		rp, err := startNamespacePlugin(selfBinary, ipCmd, runtimeBase, cfg)
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

	<-ctx.Done()
	return nil
}

func runPluginMode() error {
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

	ipCmd, err := exec.LookPath("ip")
	if err != nil {
		return fmt.Errorf("find ip command: %w", err)
	}

	parentNIC := envDefault("PARENT_NIC", "eth0")
	runtimeBase := envDefault("PLUGIN_RUNTIME_BASE", "./netforge")

	configs, err := loadConfigs(parentNIC)
	if err != nil {
		return err
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	return runHost(ctx, parentNIC, selfBinary, ipCmd, runtimeBase, configs)
}

func main() {
	if err := runMain(); err != nil {
		log.Fatal(err)
	}
}
