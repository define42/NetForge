//go:build linux

package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"

	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netns"
)

var (
	validNamespaceName    = regexp.MustCompile(`^[A-Za-z0-9._-]{1,64}$`)
	namedNetnsDir         = "/run/netns"
	hostLinkByName        = netlink.LinkByName
	readDirEntries        = os.ReadDir
	removeAllPath         = os.RemoveAll
	destroyNamespaceLinks = destroyNamespaceLinksInNetns
	deleteNamedNamespace  = netns.DeleteNamed
)

func validateNamespaceName(name string) error {
	if !validNamespaceName.MatchString(name) {
		return fmt.Errorf("invalid namespace name %q: must match %s", name, validNamespaceName.String())
	}
	return nil
}

func normalizeNSConfig(cfg NSConfig) NSConfig {
	if cfg.OpenPort == 0 {
		cfg.OpenPort = cfg.ListenPort
	}
	return cfg
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
	if err := validateNamespaceName(cfg.Name); err != nil {
		return "", err
	}

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
	if err := validateNamespaceName(cfg.Namespace); err != nil {
		return PluginConfig{}, err
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

		if err := validateNamespaceName(cfg.Name); err != nil {
			return err
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
