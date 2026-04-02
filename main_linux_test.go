//go:build linux

package main

import (
	"bufio"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netns"
)

func TestPluginConfigJSONRoundTrip(t *testing.T) {
	cfg := NSConfig{
		Name:       "nsx",
		VLANID:     42,
		IfName:     "eth0.42",
		IPCIDR:     "192.0.2.10/24",
		MAC:        "02:00:00:00:42:42",
		Gateway:    "192.0.2.1",
		ListenPort: 8080,
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
}

func TestNamespaceHTTPServiceLifecycle(t *testing.T) {
	svc := &namespaceHTTPService{cfg: PluginConfig{
		Namespace: "ns-test",
		Interface: "eth0.100",
		IPCIDR:    "192.0.2.10/24",
		MAC:       "02:00:00:00:10:10",
		Gateway:   "192.0.2.1",
	}}

	start, err := svc.StartHTTP(18080)
	if err != nil {
		t.Fatalf("StartHTTP failed: %v", err)
	}
	if start.HTTPAddr != ":18080" {
		t.Fatalf("unexpected http addr: %q", start.HTTPAddr)
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

func requireIntegration(t *testing.T) {
	t.Helper()

	if runtime.GOOS != "linux" {
		t.Fatal("linux only")
	}
	//	if os.Geteuid() != 0 {
	//		t.Fatal("integration tests require root privileges")
	//	}
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
	cmd := exec.Command("go", "build", "-o", out, ".")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Env = os.Environ()
	if err := cmd.Run(); err != nil {
		t.Fatalf("go build failed: %v", err)
	}
	return out
}

func httpGetInNamespace(ns netns.NsHandle, rawURL string) (string, int, error) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	original, err := netns.Get()
	if err != nil {
		return "", 0, err
	}
	defer original.Close()

	if err := netns.Set(ns); err != nil {
		return "", 0, err
	}
	defer netns.Set(original)

	req, err := http.NewRequest(http.MethodGet, rawURL, nil)
	if err != nil {
		return "", 0, err
	}

	addr, err := namespaceHTTPAddress(req.URL)
	if err != nil {
		return "", 0, err
	}

	conn, err := net.DialTimeout("tcp", addr, 2*time.Second)
	if err != nil {
		return "", 0, err
	}
	defer conn.Close()
	if err := conn.SetDeadline(time.Now().Add(2 * time.Second)); err != nil {
		return "", 0, err
	}

	if err := req.Write(conn); err != nil {
		return "", 0, err
	}

	resp, err := http.ReadResponse(bufio.NewReader(conn), req)
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

func waitForHTTP(t *testing.T, fn func() (string, int, error)) {
	t.Helper()

	deadline := time.Now().Add(3 * time.Second)
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

	parentName := "dmy100"
	nsName := "tns100"
	cfg := NSConfig{
		Name:       nsName,
		VLANID:     100,
		IfName:     parentName + ".100",
		IPCIDR:     "10.10.100.2/24",
		MAC:        "02:00:00:00:10:02",
		Gateway:    "10.10.100.1",
		ListenPort: 18080,
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
}

func TestExternalPluginInNamespaceEndToEnd(t *testing.T) {
	requireIntegration(t)

	parentName := "dmy200"
	nsName := "tns200"
	cfg := NSConfig{
		Name:       nsName,
		VLANID:     200,
		IfName:     parentName + ".200",
		IPCIDR:     "10.20.0.2/24",
		MAC:        "02:00:00:00:20:02",
		Gateway:    "",
		ListenPort: 18081,
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
	proc, err := startNamespacePlugin(bin, t.TempDir(), cfg)
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

	waitForHTTP(t, func() (string, int, error) {
		return httpGetInNamespace(ns, "http://127.0.0.1:18081/healthz")
	})

	body, code, err := httpGetInNamespace(ns, "http://127.0.0.1:18081/")
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
