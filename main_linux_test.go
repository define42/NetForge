//go:build linux

package main

import (
	"context"
	"io"
	"net"
	"net/http"
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

func requireRootIntegration(t *testing.T) {
	t.Helper()

	if os.Getenv("INTEGRATION") != "1" {
		t.Skip("set INTEGRATION=1 to run integration tests")
	}
	if os.Geteuid() != 0 {
		t.Skip("integration tests require root")
	}
}

func cleanupLink(t *testing.T, name string) {
	t.Helper()
	if link, err := netlink.LinkByName(name); err == nil {
		_ = netlink.LinkDel(link)
	}
}

func buildTestBinary(t *testing.T) string {
	t.Helper()

	tmpDir := t.TempDir()
	out := filepath.Join(tmpDir, "ns-demo-testbin")

	cmd := exec.Command("go", "build", "-o", out, ".")
	cmd.Env = os.Environ()
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Run(); err != nil {
		t.Fatalf("failed to build test binary: %v", err)
	}

	return out
}

func httpGetInNamespace(ns netns.NsHandle, url string) (string, int, error) {
	transport := &http.Transport{
		DisableKeepAlives: true,
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			runtime.LockOSThread()
			defer runtime.UnlockOSThread()

			orig, err := netns.Get()
			if err != nil {
				return nil, err
			}
			defer orig.Close()

			if err := netns.Set(ns); err != nil {
				return nil, err
			}
			defer netns.Set(orig)

			return (&net.Dialer{}).DialContext(ctx, network, addr)
		},
	}
	defer transport.CloseIdleConnections()

	client := &http.Client{
		Timeout:   3 * time.Second,
		Transport: transport,
	}
	resp, err := client.Get(url)
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

func TestNamespaceVLANSetup(t *testing.T) {
	requireRootIntegration(t)

	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	parentName := "dummytest0"
	nsName := "testns100"
	vlanIf := "dummytest0.100"

	cleanupLink(t, vlanIf)
	cleanupLink(t, parentName)
	_ = netns.DeleteNamed(nsName)

	parent := &netlink.Dummy{
		LinkAttrs: netlink.LinkAttrs{Name: parentName},
	}
	if err := netlink.LinkAdd(parent); err != nil {
		t.Fatalf("failed to create dummy parent: %v", err)
	}
	t.Cleanup(func() {
		cleanupLink(t, vlanIf)
		cleanupLink(t, parentName)
		_ = netns.DeleteNamed(nsName)
	})

	parentLink, err := netlink.LinkByName(parentName)
	if err != nil {
		t.Fatalf("failed to lookup parent link: %v", err)
	}
	if err := netlink.LinkSetUp(parentLink); err != nil {
		t.Fatalf("failed to bring parent up: %v", err)
	}

	ns := ensureNamespace(nsName)
	defer ns.Close()

	ensureVLANInHost(parentName, vlanIf, 100)
	moveLinkToNamespaceIfNeeded(vlanIf, ns)
	configureLinkInNamespace(ns, vlanIf, "10.10.100.2/24", "02:00:00:00:10:02", "")

	ok, err := withNamespace(ns, func() (bool, error) {
		link, err := netlink.LinkByName(vlanIf)
		if err != nil {
			return false, err
		}

		if got := link.Attrs().HardwareAddr.String(); got != "02:00:00:00:10:02" {
			t.Fatalf("unexpected MAC: got %s", got)
		}

		addrs, err := netlink.AddrList(link, netlink.FAMILY_ALL)
		if err != nil {
			return false, err
		}

		for _, a := range addrs {
			if a.IPNet != nil && a.IPNet.String() == "10.10.100.2/24" {
				return true, nil
			}
		}
		return false, nil
	})
	if err != nil {
		t.Fatalf("verification inside namespace failed: %v", err)
	}
	if !ok {
		t.Fatal("expected VLAN interface with 10.10.100.2/24 inside namespace")
	}
}

func TestPluginInNamespace_EndToEnd(t *testing.T) {
	requireRootIntegration(t)

	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	parentName := "dummyplug0"
	nsName := "plugns1"
	vlanIf := "dummyplug0.200"

	cleanupLink(t, vlanIf)
	cleanupLink(t, parentName)
	_ = netns.DeleteNamed(nsName)

	parent := &netlink.Dummy{
		LinkAttrs: netlink.LinkAttrs{Name: parentName},
	}
	if err := netlink.LinkAdd(parent); err != nil {
		t.Fatalf("failed to create dummy parent: %v", err)
	}
	t.Cleanup(func() {
		cleanupLink(t, vlanIf)
		cleanupLink(t, parentName)
		_ = netns.DeleteNamed(nsName)
	})

	parentLink, err := netlink.LinkByName(parentName)
	if err != nil {
		t.Fatalf("failed to lookup parent link: %v", err)
	}
	if err := netlink.LinkSetUp(parentLink); err != nil {
		t.Fatalf("failed to bring parent up: %v", err)
	}

	ns := ensureNamespace(nsName)
	defer ns.Close()

	ensureVLANInHost(parentName, vlanIf, 200)
	moveLinkToNamespaceIfNeeded(vlanIf, ns)
	configureLinkInNamespace(ns, vlanIf, "10.20.0.2/24", "02:00:00:00:20:02", "")

	testBin := buildTestBinary(t)

	proc, err := startPlugin(testBin, t.TempDir(), NSConfig{
		Name:       nsName,
		VLANID:     200,
		IfName:     vlanIf,
		IPCIDR:     "10.20.0.2/24",
		MAC:        "02:00:00:00:20:02",
		Gateway:    "",
		ListenPort: 18080,
	})
	if err != nil {
		t.Fatalf("startPlugin failed: %v", err)
	}
	t.Cleanup(func() {
		if proc != nil && proc.client != nil {
			proc.client.Kill()
		}
	})

	hs, err := proc.rpc.Handshake()
	if err != nil {
		t.Fatalf("Handshake failed: %v", err)
	}
	if hs.Namespace != nsName {
		t.Fatalf("unexpected namespace from handshake: got %q want %q", hs.Namespace, nsName)
	}

	st, err := proc.rpc.Status()
	if err != nil {
		t.Fatalf("Status failed: %v", err)
	}
	if !st.HTTPRunning {
		t.Fatal("expected plugin HTTP server to be running")
	}

	// Give the HTTP server a brief moment to start listening.
	time.Sleep(200 * time.Millisecond)

	body, code, err := httpGetInNamespace(ns, "http://127.0.0.1:18080/")
	if err != nil {
		t.Fatalf("namespace-local GET failed: %v", err)
	}
	if code != http.StatusOK {
		t.Fatalf("unexpected status code: got %d", code)
	}
	if !strings.Contains(body, "namespace="+nsName) {
		t.Fatalf("unexpected body: %s", body)
	}

	healthBody, code, err := httpGetInNamespace(ns, "http://127.0.0.1:18080/healthz")
	if err != nil {
		t.Fatalf("healthz GET failed: %v", err)
	}
	if code != http.StatusOK {
		t.Fatalf("unexpected /healthz status code: got %d", code)
	}
	if strings.TrimSpace(healthBody) != "ok" {
		t.Fatalf("unexpected /healthz body: %q", healthBody)
	}
}
