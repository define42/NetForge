//go:build linux

package main

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/google/nftables"
	"github.com/vishvananda/netns"
	"golang.org/x/sys/unix"
)

type fakeNamespaceFirewallConn struct {
	tables     []*nftables.Table
	chains     []*nftables.Chain
	ops        []string
	flushCount int
	flushErrAt map[int]error
}

func (f *fakeNamespaceFirewallConn) ListTablesOfFamily(family nftables.TableFamily) ([]*nftables.Table, error) {
	var out []*nftables.Table
	for _, table := range f.tables {
		if table != nil && table.Family == family {
			out = append(out, table)
		}
	}
	return out, nil
}

func (f *fakeNamespaceFirewallConn) ListChainsOfTableFamily(family nftables.TableFamily) ([]*nftables.Chain, error) {
	var out []*nftables.Chain
	for _, chain := range f.chains {
		if chain != nil && chain.Table != nil && chain.Table.Family == family {
			out = append(out, chain)
		}
	}
	return out, nil
}

func (f *fakeNamespaceFirewallConn) AddTable(t *nftables.Table) *nftables.Table {
	f.ops = append(f.ops, "add-table:"+t.Name)
	return t
}

func (f *fakeNamespaceFirewallConn) AddChain(c *nftables.Chain) *nftables.Chain {
	f.ops = append(f.ops, "add-chain:"+c.Name)
	return c
}

func (f *fakeNamespaceFirewallConn) AddRule(r *nftables.Rule) *nftables.Rule {
	f.ops = append(f.ops, "add-rule")
	return r
}

func (f *fakeNamespaceFirewallConn) DelTable(t *nftables.Table) {
	f.ops = append(f.ops, "del-table:"+t.Name)
}

func (f *fakeNamespaceFirewallConn) FlushChain(c *nftables.Chain) {
	f.ops = append(f.ops, "flush-chain:"+c.Name)
}

func (f *fakeNamespaceFirewallConn) Flush() error {
	f.flushCount++
	f.ops = append(f.ops, "flush")
	if err := f.flushErrAt[f.flushCount]; err != nil {
		return err
	}
	return nil
}

type wrappedNamespaceFirewallConn struct {
	namespaceFirewallConn
	flush func() error
}

func (w *wrappedNamespaceFirewallConn) Flush() error {
	if w.flush != nil {
		if err := w.flush(); err != nil {
			return err
		}
	}
	return w.namespaceFirewallConn.Flush()
}

func restoreNamespaceFirewallHooks() func() {
	original := newNamespaceFirewallConn
	return func() {
		newNamespaceFirewallConn = original
	}
}

func firewallStateForNamespace(t *testing.T, ns netns.NsHandle) namespaceFirewallState {
	t.Helper()

	conn, err := nftables.New(nftables.WithNetNSFd(int(ns)))
	if err != nil {
		t.Fatalf("open nftables conn failed: %v", err)
	}

	state, err := discoverNamespaceFirewallState(conn)
	if err != nil {
		t.Fatalf("discoverNamespaceFirewallState failed: %v", err)
	}
	return state
}

func TestConfigureNamespaceFirewallWithConnMissingTable(t *testing.T) {
	cfg := NSConfig{Name: "ns1", OpenPorts: []int{8080, 8443}, AllowICMP: true}
	conn := &fakeNamespaceFirewallConn{}

	if err := configureNamespaceFirewallWithConn(conn, cfg); err != nil {
		t.Fatalf("configureNamespaceFirewallWithConn failed: %v", err)
	}

	wantOps := []string{
		"add-table:" + namespaceFirewallTableName,
		"add-chain:" + namespaceFirewallInputName,
		"add-rule",
		"add-rule",
		"add-rule",
		"add-rule",
		"add-rule",
		"flush",
	}
	if strings.Join(conn.ops, ",") != strings.Join(wantOps, ",") {
		t.Fatalf("ops = %v, want %v", conn.ops, wantOps)
	}
	if conn.flushCount != 1 {
		t.Fatalf("flushCount = %d, want 1", conn.flushCount)
	}
}

func TestConfigureNamespaceFirewallWithConnExistingTable(t *testing.T) {
	table := namespaceFirewallTableSpec()
	chain := namespaceFirewallInputChainSpec(table)
	conn := &fakeNamespaceFirewallConn{
		tables: []*nftables.Table{table},
		chains: []*nftables.Chain{chain},
	}

	if err := configureNamespaceFirewallWithConn(conn, NSConfig{Name: "ns1"}); err != nil {
		t.Fatalf("configureNamespaceFirewallWithConn failed: %v", err)
	}

	wantOps := []string{
		"flush-chain:" + namespaceFirewallInputName,
		"add-rule",
		"flush",
	}
	if strings.Join(conn.ops, ",") != strings.Join(wantOps, ",") {
		t.Fatalf("ops = %v, want %v", conn.ops, wantOps)
	}
	if conn.flushCount != 1 {
		t.Fatalf("flushCount = %d, want 1", conn.flushCount)
	}
}

func TestConfigureNamespaceFirewallWithConnStructuralDrift(t *testing.T) {
	table := namespaceFirewallTableSpec()
	chain := namespaceFirewallInputChainSpec(table)
	policyAccept := nftables.ChainPolicyAccept
	chain.Policy = &policyAccept

	conn := &fakeNamespaceFirewallConn{
		tables: []*nftables.Table{table},
		chains: []*nftables.Chain{chain},
	}

	if err := configureNamespaceFirewallWithConn(conn, NSConfig{Name: "ns1"}); err != nil {
		t.Fatalf("configureNamespaceFirewallWithConn failed: %v", err)
	}

	wantOps := []string{
		"del-table:" + namespaceFirewallTableName,
		"add-table:" + namespaceFirewallTableName,
		"add-chain:" + namespaceFirewallInputName,
		"add-rule",
		"flush",
	}
	if strings.Join(conn.ops, ",") != strings.Join(wantOps, ",") {
		t.Fatalf("ops = %v, want %v", conn.ops, wantOps)
	}
	if conn.flushCount != 1 {
		t.Fatalf("flushCount = %d, want 1", conn.flushCount)
	}
}

func TestConfigureNamespaceFirewallReconfigureIntegration(t *testing.T) {
	requireIntegration(t)

	token := uniqueNamespaceToken()
	nsName := "tnsfw" + token
	_ = netns.DeleteNamed(nsName)

	ns, err := ensureNamedNamespace(nsName)
	if err != nil {
		t.Fatalf("ensureNamedNamespace failed: %v", err)
	}
	t.Cleanup(func() {
		_ = ns.Close()
		cleanupNamespaceSet("", []string{nsName})
	})

	cfg := NSConfig{Name: nsName, OpenPorts: []int{18080, 18443}, AllowICMP: true}
	if err := configureNamespaceFirewall(ns, cfg); err != nil {
		t.Fatalf("initial configureNamespaceFirewall failed: %v", err)
	}

	updated := cfg
	updated.OpenPorts = []int{18443}
	updated.AllowICMP = false
	if err := configureNamespaceFirewall(ns, updated); err != nil {
		t.Fatalf("updated configureNamespaceFirewall failed: %v", err)
	}

	state := firewallStateForNamespace(t, ns)
	if state.table == nil || state.inputChain == nil || state.replaceTable {
		t.Fatalf("unexpected firewall state after reconfigure: %+v", state)
	}
	if state.inputChain.Policy == nil || *state.inputChain.Policy != nftables.ChainPolicyDrop {
		t.Fatalf("unexpected chain policy after reconfigure: %+v", state.inputChain.Policy)
	}

	allowsPort, err := namespaceFirewallAllowsTCPPort(ns, cfg.OpenPorts[0])
	if err != nil {
		t.Fatalf("namespaceFirewallAllowsTCPPort failed: %v", err)
	}
	if allowsPort {
		t.Fatalf("stale tcp port %d remained allowed", cfg.OpenPorts[0])
	}

	allowsPort, err = namespaceFirewallAllowsTCPPort(ns, updated.OpenPorts[0])
	if err != nil {
		t.Fatalf("namespaceFirewallAllowsTCPPort failed: %v", err)
	}
	if !allowsPort {
		t.Fatalf("updated tcp port %d was not allowed", updated.OpenPorts[0])
	}

	allowsICMP, err := namespaceFirewallAllowsProtocol(ns, unix.IPPROTO_ICMP)
	if err != nil {
		t.Fatalf("namespaceFirewallAllowsProtocol failed: %v", err)
	}
	if allowsICMP {
		t.Fatal("icmp remained allowed after reconfigure")
	}
}

func TestConfigureNamespaceFirewallFlushFailurePreservesFirewall(t *testing.T) {
	requireIntegration(t)

	token := uniqueNamespaceToken()
	nsName := "tnsfw" + token
	_ = netns.DeleteNamed(nsName)

	ns, err := ensureNamedNamespace(nsName)
	if err != nil {
		t.Fatalf("ensureNamedNamespace failed: %v", err)
	}
	t.Cleanup(func() {
		_ = ns.Close()
		cleanupNamespaceSet("", []string{nsName})
	})

	cfg := NSConfig{Name: nsName, OpenPorts: []int{19080}, AllowICMP: true}
	if err := configureNamespaceFirewall(ns, cfg); err != nil {
		t.Fatalf("initial configureNamespaceFirewall failed: %v", err)
	}

	restore := restoreNamespaceFirewallHooks()
	defer restore()

	realFactory := newNamespaceFirewallConn
	newNamespaceFirewallConn = func(ns netns.NsHandle) (namespaceFirewallConn, error) {
		conn, err := realFactory(ns)
		if err != nil {
			return nil, err
		}
		return &wrappedNamespaceFirewallConn{
			namespaceFirewallConn: conn,
			flush: func() error {
				return errors.New("injected nftables flush failure")
			},
		}, nil
	}

	err = configureNamespaceFirewall(ns, NSConfig{Name: nsName, OpenPorts: []int{}, AllowICMP: false})
	if err == nil || !strings.Contains(err.Error(), "injected nftables flush failure") {
		t.Fatalf("configureNamespaceFirewall error = %v, want injected flush failure", err)
	}

	state := firewallStateForNamespace(t, ns)
	if state.table == nil || state.inputChain == nil || state.replaceTable {
		t.Fatalf("unexpected firewall state after failed update: %+v", state)
	}
	if state.inputChain.Policy == nil || *state.inputChain.Policy != nftables.ChainPolicyDrop {
		t.Fatalf("unexpected chain policy after failed update: %+v", state.inputChain.Policy)
	}

	allowsPort, err := namespaceFirewallAllowsTCPPort(ns, cfg.OpenPorts[0])
	if err != nil {
		t.Fatalf("namespaceFirewallAllowsTCPPort failed: %v", err)
	}
	if !allowsPort {
		t.Fatalf("existing tcp port %d was not preserved after failed update", cfg.OpenPorts[0])
	}

	allowsICMP, err := namespaceFirewallAllowsProtocol(ns, unix.IPPROTO_ICMP)
	if err != nil {
		t.Fatalf("namespaceFirewallAllowsProtocol failed: %v", err)
	}
	if !allowsICMP {
		t.Fatal("existing icmp rule was not preserved after failed update")
	}
}

func TestConfigureNamespaceFirewallOpensConnectionError(t *testing.T) {
	restore := restoreNamespaceFirewallHooks()
	defer restore()

	newNamespaceFirewallConn = func(netns.NsHandle) (namespaceFirewallConn, error) {
		return nil, fmt.Errorf("boom")
	}

	err := configureNamespaceFirewall(netns.None(), NSConfig{Name: "ns1"})
	if err == nil || !strings.Contains(err.Error(), "open nftables connection in ns1: boom") {
		t.Fatalf("configureNamespaceFirewall error = %v", err)
	}
}

func TestConfigureNamespaceFirewallRejectsInvalidPort(t *testing.T) {
	err := configureNamespaceFirewallWithConn(&fakeNamespaceFirewallConn{}, NSConfig{Name: "ns1", OpenPorts: []int{-1}})
	if err == nil {
		t.Fatal("configureNamespaceFirewallWithConn succeeded, want error")
	}
}

func TestLookupNFTablesTableByFamily(t *testing.T) {
	conn := &fakeNamespaceFirewallConn{
		tables: []*nftables.Table{
			{Name: "other", Family: nftables.TableFamilyINet},
			{Name: namespaceFirewallTableName, Family: nftables.TableFamilyINet},
		},
	}

	table, err := lookupNFTablesTableByFamily(conn, nftables.TableFamilyINet, namespaceFirewallTableName)
	if err != nil {
		t.Fatalf("lookupNFTablesTableByFamily failed: %v", err)
	}
	if table == nil || table.Name != namespaceFirewallTableName {
		t.Fatalf("unexpected table: %+v", table)
	}
}
