//go:build linux

package main

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netns"
)

func restoreReconcileTestHooks() func() {
	originalNamedNetnsDir := namedNetnsDir
	originalHostLinkByName := hostLinkByName
	originalReadDirEntries := readDirEntries
	originalRemoveAllPath := removeAllPath
	originalDestroyNamespaceLinks := destroyNamespaceLinks
	originalDeleteNamedNamespace := deleteNamedNamespace

	return func() {
		namedNetnsDir = originalNamedNetnsDir
		hostLinkByName = originalHostLinkByName
		readDirEntries = originalReadDirEntries
		removeAllPath = originalRemoveAllPath
		destroyNamespaceLinks = originalDestroyNamespaceLinks
		deleteNamedNamespace = originalDeleteNamedNamespace
	}
}

func namespaceExists(t *testing.T, name string) bool {
	t.Helper()

	ns, err := netns.GetFromName(name)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return false
		}
		t.Fatalf("lookup namespace %q failed: %v", name, err)
	}
	_ = ns.Close()
	return true
}

func shortRuntimeBase(t *testing.T, token string) string {
	t.Helper()

	base := filepath.Join(os.TempDir(), "nf-"+token)
	_ = os.RemoveAll(base)
	if err := os.MkdirAll(base, 0o755); err != nil {
		t.Fatalf("mkdir runtime base failed: %v", err)
	}
	t.Cleanup(func() {
		_ = os.RemoveAll(base)
	})
	return base
}

func TestValidateHostConfig(t *testing.T) {
	restore := restoreReconcileTestHooks()
	defer restore()

	hostLinkByName = func(name string) (netlink.Link, error) {
		if name != "parent0" {
			return nil, fmt.Errorf("link %q not found", name)
		}
		link := &netlink.Dummy{LinkAttrs: netlink.NewLinkAttrs()}
		link.LinkAttrs.Name = name
		return link, nil
	}

	valid := NSConfig{
		Name:       "ns1",
		VLANID:     100,
		IfName:     "parent0.100",
		IPCIDR:     "10.10.0.2/24",
		MAC:        "02:00:00:00:10:02",
		Gateway:    "10.10.0.1",
		ListenPort: 18080,
		OpenPorts:  []int{18080},
	}

	tests := []struct {
		name      string
		parentNIC string
		configs   []NSConfig
		wantErr   string
	}{
		{
			name:      "valid",
			parentNIC: "parent0",
			configs:   []NSConfig{valid},
		},
		{
			name:      "valid namespace characters",
			parentNIC: "parent0",
			configs: []NSConfig{{
				Name:       "ns_Name-01",
				VLANID:     101,
				IfName:     "parent0.101",
				IPCIDR:     "10.10.1.2/24",
				ListenPort: 8080,
				OpenPorts:  []int{8080},
			}},
		},
		{
			name:      "missing parent",
			parentNIC: "missing0",
			configs:   []NSConfig{valid},
			wantErr:   `lookup parent link "missing0"`,
		},
		{
			name:      "duplicate namespace",
			parentNIC: "parent0",
			configs:   []NSConfig{valid, valid},
			wantErr:   `duplicate namespace name "ns1"`,
		},
		{
			name:      "duplicate interface",
			parentNIC: "parent0",
			configs: []NSConfig{
				valid,
				{
					Name:       "ns2",
					VLANID:     200,
					IfName:     valid.IfName,
					IPCIDR:     "10.20.0.2/24",
					ListenPort: 80,
					OpenPorts:  []int{80},
				},
			},
			wantErr: `duplicate interface name "parent0.100"`,
		},
		{
			name:      "empty namespace name",
			parentNIC: "parent0",
			configs: []NSConfig{{
				Name:       "",
				VLANID:     100,
				IfName:     "parent0.100",
				IPCIDR:     "10.10.0.2/24",
				ListenPort: 80,
				OpenPorts:  []int{80},
			}},
			wantErr: `invalid namespace name ""`,
		},
		{
			name:      "namespace name has slash",
			parentNIC: "parent0",
			configs: []NSConfig{{
				Name:       "ns/1",
				VLANID:     100,
				IfName:     "parent0.100",
				IPCIDR:     "10.10.0.2/24",
				ListenPort: 80,
				OpenPorts:  []int{80},
			}},
			wantErr: `invalid namespace name "ns/1"`,
		},
		{
			name:      "namespace name has dot",
			parentNIC: "parent0",
			configs: []NSConfig{{
				Name:       "ns.1",
				VLANID:     100,
				IfName:     "parent0.100",
				IPCIDR:     "10.10.0.2/24",
				ListenPort: 80,
				OpenPorts:  []int{80},
			}},
			wantErr: `invalid namespace name "ns.1"`,
		},
		{
			name:      "namespace name too long",
			parentNIC: "parent0",
			configs: []NSConfig{{
				Name:       strings.Repeat("a", 65),
				VLANID:     100,
				IfName:     "parent0.100",
				IPCIDR:     "10.10.0.2/24",
				ListenPort: 80,
				OpenPorts:  []int{80},
			}},
			wantErr: `must match ^[A-Za-z0-9_-]{1,64}$`,
		},
		{
			name:      "bad vlan id zero",
			parentNIC: "parent0",
			configs: []NSConfig{{
				Name:       "ns1",
				VLANID:     0,
				IfName:     "parent0.100",
				IPCIDR:     "10.10.0.2/24",
				ListenPort: 80,
				OpenPorts:  []int{80},
			}},
			wantErr: `invalid vlan id 0`,
		},
		{
			name:      "bad vlan id too high",
			parentNIC: "parent0",
			configs: []NSConfig{{
				Name:       "ns1",
				VLANID:     4095,
				IfName:     "parent0.100",
				IPCIDR:     "10.10.0.2/24",
				ListenPort: 80,
				OpenPorts:  []int{80},
			}},
			wantErr: `invalid vlan id 4095`,
		},
		{
			name:      "bad listen port zero",
			parentNIC: "parent0",
			configs: []NSConfig{{
				Name:       "ns1",
				VLANID:     100,
				IfName:     "parent0.100",
				IPCIDR:     "10.10.0.2/24",
				ListenPort: 0,
				OpenPorts:  []int{80},
			}},
			wantErr: `invalid listen port 0`,
		},
		{
			name:      "bad listen port too high",
			parentNIC: "parent0",
			configs: []NSConfig{{
				Name:       "ns1",
				VLANID:     100,
				IfName:     "parent0.100",
				IPCIDR:     "10.10.0.2/24",
				ListenPort: 70000,
				OpenPorts:  []int{80},
			}},
			wantErr: `invalid listen port 70000`,
		},
		{
			name:      "bad ip",
			parentNIC: "parent0",
			configs: []NSConfig{
				{
					Name:       "ns1",
					VLANID:     100,
					IfName:     "parent0.100",
					IPCIDR:     "bad",
					ListenPort: 80,
					OpenPorts:  []int{80},
				},
			},
			wantErr: `parse ip "bad"`,
		},
		{
			name:      "bad mac",
			parentNIC: "parent0",
			configs: []NSConfig{
				{
					Name:       "ns1",
					VLANID:     100,
					IfName:     "parent0.100",
					IPCIDR:     "10.10.0.2/24",
					MAC:        "bad-mac",
					ListenPort: 80,
					OpenPorts:  []int{80},
				},
			},
			wantErr: `parse mac "bad-mac"`,
		},
		{
			name:      "bad gateway",
			parentNIC: "parent0",
			configs: []NSConfig{
				{
					Name:       "ns1",
					VLANID:     100,
					IfName:     "parent0.100",
					IPCIDR:     "10.10.0.2/24",
					Gateway:    "bad-gateway",
					ListenPort: 80,
					OpenPorts:  []int{80},
				},
			},
			wantErr: `invalid gateway "bad-gateway"`,
		},
		{
			name:      "bad open port",
			parentNIC: "parent0",
			configs: []NSConfig{
				{
					Name:       "ns1",
					VLANID:     100,
					IfName:     "parent0.100",
					IPCIDR:     "10.10.0.2/24",
					ListenPort: 80,
					OpenPorts:  []int{70000},
				},
			},
			wantErr: `invalid open port 70000`,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := validateHostConfig(tc.parentNIC, tc.configs)
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("validateHostConfig returned error: %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("validateHostConfig error = %v, want substring %q", err, tc.wantErr)
			}
		})
	}
}

func TestListNamedNamespaces(t *testing.T) {
	restore := restoreReconcileTestHooks()
	defer restore()

	namedNetnsDir = t.TempDir()
	if err := os.WriteFile(filepath.Join(namedNetnsDir, "ns-b"), []byte("b"), 0o644); err != nil {
		t.Fatalf("write ns-b failed: %v", err)
	}
	if err := os.WriteFile(filepath.Join(namedNetnsDir, "ns-a"), []byte("a"), 0o644); err != nil {
		t.Fatalf("write ns-a failed: %v", err)
	}
	if err := os.Mkdir(filepath.Join(namedNetnsDir, "subdir"), 0o755); err != nil {
		t.Fatalf("mkdir subdir failed: %v", err)
	}

	got, err := listNamedNamespaces()
	if err != nil {
		t.Fatalf("listNamedNamespaces failed: %v", err)
	}
	want := []string{"ns-a", "ns-b"}
	if len(got) != len(want) {
		t.Fatalf("listNamedNamespaces length = %d, want %d (%v)", len(got), len(want), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("listNamedNamespaces[%d] = %q, want %q", i, got[i], want[i])
		}
	}
}

func TestDestroyNamespaceStateRemovesRuntimeDir(t *testing.T) {
	restore := restoreReconcileTestHooks()
	defer restore()

	runtimeBase := t.TempDir()
	runtimeDir := filepath.Join(runtimeBase, "ns1")
	if err := os.MkdirAll(runtimeDir, 0o755); err != nil {
		t.Fatalf("mkdir runtime dir failed: %v", err)
	}

	var destroyedName string
	var deletedName string
	destroyNamespaceLinks = func(name string) error {
		destroyedName = name
		return nil
	}
	deleteNamedNamespace = func(name string) error {
		deletedName = name
		return nil
	}

	if err := destroyNamespaceState("ns1", runtimeBase); err != nil {
		t.Fatalf("destroyNamespaceState failed: %v", err)
	}
	if destroyedName != "ns1" {
		t.Fatalf("destroyNamespaceLinks called with %q, want %q", destroyedName, "ns1")
	}
	if deletedName != "ns1" {
		t.Fatalf("deleteNamedNamespace called with %q, want %q", deletedName, "ns1")
	}
	if _, err := os.Stat(runtimeDir); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("runtime dir still exists or unexpected error: %v", err)
	}
}

func TestReconcileNamespacesRecreatesDriftedNamespace(t *testing.T) {
	requireIntegration(t)

	token := uniqueNamespaceToken()
	parentName := "d" + token
	nsName := "tns" + token
	ifName := parentName + ".ns"
	runtimeBase := t.TempDir()

	cleanupHostLink(ifName)
	cleanupHostLink(parentName)
	cleanupNamespaceSet(runtimeBase, []string{nsName})

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

	t.Cleanup(func() {
		cleanupNamespaceSet(runtimeBase, []string{nsName})
		cleanupHostLink(ifName)
		cleanupHostLink(parentName)
	})

	initial := NSConfig{
		Name:       nsName,
		VLANID:     100,
		IfName:     ifName,
		IPCIDR:     "10.10.100.2/24",
		MAC:        "02:00:00:00:10:02",
		Gateway:    "10.10.100.1",
		ListenPort: 18080,
		OpenPorts:  []int{18080},
	}
	if _, err := reconcileNamespaces(parentName, runtimeBase, []NSConfig{initial}); err != nil {
		t.Fatalf("initial reconcileNamespaces failed: %v", err)
	}

	updated := initial
	updated.VLANID = 200
	updated.IPCIDR = "10.20.0.2/24"
	updated.Gateway = ""
	if _, err := reconcileNamespaces(parentName, runtimeBase, []NSConfig{updated}); err != nil {
		t.Fatalf("updated reconcileNamespaces failed: %v", err)
	}

	ns, err := netns.GetFromName(nsName)
	if err != nil {
		t.Fatalf("lookup namespace failed: %v", err)
	}
	defer ns.Close()

	handle, err := netlink.NewHandleAt(ns)
	if err != nil {
		t.Fatalf("NewHandleAt failed: %v", err)
	}
	defer handle.Delete()

	link, err := handle.LinkByName(ifName)
	if err != nil {
		t.Fatalf("lookup link in namespace failed: %v", err)
	}
	vlan, ok := link.(*netlink.Vlan)
	if !ok {
		t.Fatalf("link type = %T, want *netlink.Vlan", link)
	}
	if vlan.VlanId != updated.VLANID {
		t.Fatalf("vlan id = %d, want %d", vlan.VlanId, updated.VLANID)
	}

	addrs, err := handle.AddrList(link, netlink.FAMILY_V4)
	if err != nil {
		t.Fatalf("AddrList failed: %v", err)
	}
	if len(addrs) != 1 {
		t.Fatalf("address count = %d, want 1 (%+v)", len(addrs), addrs)
	}
	if addrs[0].IPNet == nil || addrs[0].IPNet.String() != updated.IPCIDR {
		t.Fatalf("address = %v, want %s", addrs[0].IPNet, updated.IPCIDR)
	}

	routes, err := handle.RouteList(link, netlink.FAMILY_V4)
	if err != nil {
		t.Fatalf("RouteList failed: %v", err)
	}
	for _, route := range routes {
		if routeIsDefaultV4(route) {
			t.Fatalf("unexpected default route remained: %+v", route)
		}
	}
}

func TestReconcileNamespacesRemovesStaleNamespaceAndRuntimeDir(t *testing.T) {
	requireIntegration(t)

	token := uniqueNamespaceToken()
	parentName := "d" + token
	desiredName := "tns" + token + "a"
	staleName := "tns" + token + "b"
	ifName := parentName + ".300"
	runtimeBase := t.TempDir()

	cleanupHostLink(ifName)
	cleanupHostLink(parentName)
	cleanupNamespaceSet(runtimeBase, []string{desiredName, staleName})

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

	staleNS, err := ensureNamedNamespace(staleName)
	if err != nil {
		t.Fatalf("ensureNamedNamespace(%q) failed: %v", staleName, err)
	}
	_ = staleNS.Close()
	if err := os.MkdirAll(filepath.Join(runtimeBase, staleName), 0o755); err != nil {
		t.Fatalf("mkdir stale runtime dir failed: %v", err)
	}
	if err := os.MkdirAll(filepath.Join(runtimeBase, desiredName), 0o755); err != nil {
		t.Fatalf("mkdir desired runtime dir failed: %v", err)
	}

	t.Cleanup(func() {
		cleanupNamespaceSet(runtimeBase, []string{desiredName, staleName})
		cleanupHostLink(ifName)
		cleanupHostLink(parentName)
	})

	cfg := NSConfig{
		Name:       desiredName,
		VLANID:     300,
		IfName:     ifName,
		IPCIDR:     "10.30.0.2/24",
		MAC:        "02:00:00:00:30:02",
		Gateway:    "10.30.0.1",
		ListenPort: 18081,
		OpenPorts:  []int{18081},
	}
	if _, err := reconcileNamespaces(parentName, runtimeBase, []NSConfig{cfg}); err != nil {
		t.Fatalf("reconcileNamespaces failed: %v", err)
	}

	if namespaceExists(t, staleName) {
		t.Fatalf("stale namespace %q still exists", staleName)
	}
	if _, err := os.Stat(filepath.Join(runtimeBase, staleName)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("stale runtime dir still exists or unexpected error: %v", err)
	}
	if _, err := os.Stat(filepath.Join(runtimeBase, desiredName)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("desired runtime dir should have been removed before rebuild: %v", err)
	}
	if !namespaceExists(t, desiredName) {
		t.Fatalf("desired namespace %q was not recreated", desiredName)
	}
}

func TestRunHostReconcilesNamespacesAndStartsPlugins(t *testing.T) {
	requireIntegration(t)

	token := uniqueNamespaceToken()
	parentName := "d" + token
	nsName := "tns" + token
	staleName := nsName + "stale"
	ifName := parentName + ".400"
	runtimeBase := shortRuntimeBase(t, token)
	hostPort := freeLocalTCPPort(t)
	listenPort := freeLocalTCPPort(t)

	cleanupHostLink(ifName)
	cleanupHostLink(parentName)
	cleanupNamespaceSet(runtimeBase, []string{nsName, staleName})

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

	staleNS, err := ensureNamedNamespace(staleName)
	if err != nil {
		t.Fatalf("ensureNamedNamespace(%q) failed: %v", staleName, err)
	}
	_ = staleNS.Close()
	if err := os.MkdirAll(filepath.Join(runtimeBase, staleName), 0o755); err != nil {
		t.Fatalf("mkdir stale runtime dir failed: %v", err)
	}

	oldCfg := NSConfig{
		Name:       nsName,
		VLANID:     401,
		IfName:     ifName,
		IPCIDR:     "10.40.1.2/24",
		MAC:        "02:00:00:00:40:02",
		Gateway:    "10.40.1.1",
		ListenPort: listenPort,
		OpenPorts:  []int{listenPort},
	}
	if _, err := reconcileNamespaces(parentName, runtimeBase, []NSConfig{oldCfg}); err != nil {
		t.Fatalf("seed reconcileNamespaces failed: %v", err)
	}

	cfg := oldCfg
	cfg.VLANID = 402
	cfg.IPCIDR = "10.40.2.2/24"
	cfg.Gateway = ""

	selfBinary := buildPackageBinary(t)
	ctx, cancel := context.WithCancel(context.Background())
	errCh := make(chan error, 1)
	go func() {
		errCh <- runHost(ctx, parentName, selfBinary, runtimeBase, fmt.Sprintf("127.0.0.1:%d", hostPort), []NSConfig{cfg})
	}()

	waitForHTTP(t, func() (string, int, error) {
		resp, err := http.Get(fmt.Sprintf("http://127.0.0.1:%d/healthz", hostPort))
		if err != nil {
			return "", 0, err
		}
		defer resp.Body.Close()
		return resp.Status, resp.StatusCode, nil
	})
	waitForHTTP(t, func() (string, int, error) {
		return httpGetInNamespace(nsName, fmt.Sprintf("http://127.0.0.1:%d/healthz", listenPort))
	})

	body, code, err := httpGetInNamespace(nsName, fmt.Sprintf("http://127.0.0.1:%d/", listenPort))
	if err != nil {
		t.Fatalf("namespace GET / failed: %v", err)
	}
	if code != http.StatusOK {
		t.Fatalf("unexpected status code: got %d", code)
	}
	if !strings.Contains(body, "namespace="+nsName) {
		t.Fatalf("unexpected body: %s", body)
	}
	if namespaceExists(t, staleName) {
		t.Fatalf("stale namespace %q still exists after runHost startup", staleName)
	}
	if _, err := os.Stat(filepath.Join(runtimeBase, staleName)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("stale runtime dir still exists or unexpected error: %v", err)
	}

	cancel()
	if err := <-errCh; err != nil {
		t.Fatalf("runHost returned error: %v", err)
	}

	cleanupNamespaceSet(runtimeBase, []string{nsName, staleName})
	cleanupHostLink(ifName)
	cleanupHostLink(parentName)
}

func TestRunHostCleansRecreatedNamespacesOnStartupFailure(t *testing.T) {
	requireIntegration(t)

	token := uniqueNamespaceToken()
	parentName := "d" + token
	nsName := "tns" + token
	conflictName := "c" + token
	ifName := parentName + ".500"
	runtimeBase := shortRuntimeBase(t, token+"f")
	hostPort := freeLocalTCPPort(t)

	cleanupHostLink(conflictName)
	cleanupHostLink(ifName)
	cleanupHostLink(parentName)
	cleanupNamespaceSet(runtimeBase, []string{nsName, nsName + "2"})

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

	conflict := &netlink.Dummy{LinkAttrs: netlink.NewLinkAttrs()}
	conflict.LinkAttrs.Name = conflictName
	if err := netlink.LinkAdd(conflict); err != nil {
		t.Fatalf("create conflicting host link failed: %v", err)
	}

	t.Cleanup(func() {
		cleanupNamespaceSet(runtimeBase, []string{nsName, nsName + "2"})
		cleanupHostLink(conflictName)
		cleanupHostLink(ifName)
		cleanupHostLink(parentName)
	})

	cfg1 := NSConfig{
		Name:       nsName,
		VLANID:     500,
		IfName:     ifName,
		IPCIDR:     "10.50.0.2/24",
		MAC:        "02:00:00:00:50:02",
		Gateway:    "10.50.0.1",
		ListenPort: 18082,
		OpenPorts:  []int{18082},
	}
	cfg2 := NSConfig{
		Name:       nsName + "2",
		VLANID:     501,
		IfName:     conflictName,
		IPCIDR:     "10.51.0.2/24",
		MAC:        "02:00:00:00:51:02",
		Gateway:    "10.51.0.1",
		ListenPort: 18083,
		OpenPorts:  []int{18083},
	}

	selfBinary := buildPackageBinary(t)
	err = runHost(context.Background(), parentName, selfBinary, runtimeBase, fmt.Sprintf("127.0.0.1:%d", hostPort), []NSConfig{cfg1, cfg2})
	if err == nil {
		t.Fatal("runHost succeeded, want error")
	}
	if !strings.Contains(err.Error(), `existing link "`+conflictName+`"`) {
		t.Fatalf("runHost error = %v, want conflicting link error", err)
	}
	if namespaceExists(t, cfg1.Name) {
		t.Fatalf("namespace %q still exists after startup failure", cfg1.Name)
	}
	if namespaceExists(t, cfg2.Name) {
		t.Fatalf("namespace %q still exists after startup failure", cfg2.Name)
	}
	if _, err := os.Stat(filepath.Join(runtimeBase, cfg1.Name)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("runtime dir for %q still exists or unexpected error: %v", cfg1.Name, err)
	}
	if _, err := os.Stat(filepath.Join(runtimeBase, cfg2.Name)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("runtime dir for %q still exists or unexpected error: %v", cfg2.Name, err)
	}
	if _, err := netlink.LinkByName(cfg1.IfName); err == nil {
		t.Fatalf("host link %q leaked back into the host namespace", cfg1.IfName)
	}
	if _, err := netlink.LinkByName(conflictName); err != nil {
		t.Fatalf("conflicting host link %q should remain: %v", conflictName, err)
	}
}
