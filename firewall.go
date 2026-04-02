//go:build linux

package main

import (
	"fmt"

	"github.com/google/nftables"
	"github.com/google/nftables/binaryutil"
	"github.com/google/nftables/expr"
	"github.com/vishvananda/netns"
	"golang.org/x/sys/unix"
)

const (
	namespaceFirewallTableName   = "netforge"
	namespaceFirewallInputName   = "input"
	namespaceFirewallForwardName = "forward"
)

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

type nftablesTableLister interface {
	ListTablesOfFamily(family nftables.TableFamily) ([]*nftables.Table, error)
}

type namespaceFirewallConn interface {
	nftablesTableLister
	ListChainsOfTableFamily(family nftables.TableFamily) ([]*nftables.Chain, error)
	AddTable(t *nftables.Table) *nftables.Table
	AddChain(c *nftables.Chain) *nftables.Chain
	AddRule(r *nftables.Rule) *nftables.Rule
	DelTable(t *nftables.Table)
	FlushChain(c *nftables.Chain)
	Flush() error
}

type namespaceFirewallState struct {
	table        *nftables.Table
	inputChain   *nftables.Chain
	forwardChain *nftables.Chain
	replaceTable bool
}

var newNamespaceFirewallConn = func(ns netns.NsHandle) (namespaceFirewallConn, error) {
	return nftables.New(nftables.WithNetNSFd(int(ns)))
}

func lookupNFTablesTableByFamily(conn nftablesTableLister, family nftables.TableFamily, name string) (*nftables.Table, error) {
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

func namespaceFirewallTableSpec() *nftables.Table {
	return &nftables.Table{
		Family: nftables.TableFamilyINet,
		Name:   namespaceFirewallTableName,
	}
}

func namespaceFirewallInputChainSpec(table *nftables.Table) *nftables.Chain {
	policyDrop := nftables.ChainPolicyDrop
	return &nftables.Chain{
		Name:     namespaceFirewallInputName,
		Table:    table,
		Type:     nftables.ChainTypeFilter,
		Hooknum:  nftables.ChainHookInput,
		Priority: nftables.ChainPriorityFilter,
		Policy:   &policyDrop,
	}
}

func namespaceFirewallForwardChainSpec(table *nftables.Table) *nftables.Chain {
	policyDrop := nftables.ChainPolicyDrop
	return &nftables.Chain{
		Name:     namespaceFirewallForwardName,
		Table:    table,
		Type:     nftables.ChainTypeFilter,
		Hooknum:  nftables.ChainHookForward,
		Priority: nftables.ChainPriorityFilter,
		Policy:   &policyDrop,
	}
}

func nftablesInterfaceName(name string) []byte {
	data := make([]byte, 16)
	copy(data, []byte(name+"\x00"))
	return data
}

func isNamespaceFirewallBaseChain(chain *nftables.Chain, name string, hook *nftables.ChainHook) bool {
	if chain == nil || chain.Name != name || chain.Type != nftables.ChainTypeFilter || chain.Device != "" {
		return false
	}
	if chain.Hooknum == nil || *chain.Hooknum != *hook {
		return false
	}
	if chain.Priority == nil || *chain.Priority != *nftables.ChainPriorityFilter {
		return false
	}
	if chain.Policy == nil || *chain.Policy != nftables.ChainPolicyDrop {
		return false
	}
	return true
}

func isNamespaceFirewallInputChain(chain *nftables.Chain) bool {
	return isNamespaceFirewallBaseChain(chain, namespaceFirewallInputName, nftables.ChainHookInput)
}

func isNamespaceFirewallForwardChain(chain *nftables.Chain) bool {
	return isNamespaceFirewallBaseChain(chain, namespaceFirewallForwardName, nftables.ChainHookForward)
}

func discoverNamespaceFirewallState(conn namespaceFirewallConn) (namespaceFirewallState, error) {
	table, err := lookupNFTablesTableByFamily(conn, nftables.TableFamilyINet, namespaceFirewallTableName)
	if err != nil {
		return namespaceFirewallState{}, err
	}
	if table == nil {
		return namespaceFirewallState{}, nil
	}

	chains, err := conn.ListChainsOfTableFamily(nftables.TableFamilyINet)
	if err != nil {
		return namespaceFirewallState{}, err
	}

	var tableChains []*nftables.Chain
	for _, chain := range chains {
		if chain == nil || chain.Table == nil {
			continue
		}
		if chain.Table.Family == nftables.TableFamilyINet && chain.Table.Name == table.Name {
			chain.Table = table
			tableChains = append(tableChains, chain)
		}
	}

	if len(tableChains) != 2 {
		return namespaceFirewallState{table: table, replaceTable: true}, nil
	}

	state := namespaceFirewallState{table: table}
	for _, chain := range tableChains {
		switch {
		case isNamespaceFirewallInputChain(chain):
			state.inputChain = chain
		case isNamespaceFirewallForwardChain(chain):
			state.forwardChain = chain
		default:
			return namespaceFirewallState{table: table, replaceTable: true}, nil
		}
	}
	if state.inputChain == nil || state.forwardChain == nil {
		return namespaceFirewallState{table: table, replaceTable: true}, nil
	}

	return state, nil
}

func queueNamespaceFirewallRules(conn namespaceFirewallConn, table *nftables.Table, input *nftables.Chain, cfg NSConfig) {
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

	for _, openPort := range cfg.OpenPorts {
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
				&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: binaryutil.BigEndian.PutUint16(uint16(openPort))},
				&expr.Verdict{Kind: expr.VerdictAccept},
			},
		})
	}
}

func configureNamespaceFirewallWithConn(conn namespaceFirewallConn, cfg NSConfig) error {
	cfg = normalizeNSConfig(cfg)

	for _, port := range cfg.OpenPorts {
		if port < 1 || port > 65535 {
			return fmt.Errorf("invalid open port %d", port)
		}
	}

	state, err := discoverNamespaceFirewallState(conn)
	if err != nil {
		return err
	}

	switch {
	case state.table == nil:
		table := conn.AddTable(namespaceFirewallTableSpec())
		input := conn.AddChain(namespaceFirewallInputChainSpec(table))
		conn.AddChain(namespaceFirewallForwardChainSpec(table))
		queueNamespaceFirewallRules(conn, table, input, cfg)
	case state.replaceTable:
		conn.DelTable(state.table)
		table := conn.AddTable(namespaceFirewallTableSpec())
		input := conn.AddChain(namespaceFirewallInputChainSpec(table))
		conn.AddChain(namespaceFirewallForwardChainSpec(table))
		queueNamespaceFirewallRules(conn, table, input, cfg)
	default:
		conn.FlushChain(state.inputChain)
		conn.FlushChain(state.forwardChain)
		queueNamespaceFirewallRules(conn, state.table, state.inputChain, cfg)
	}

	return conn.Flush()
}

func configureNamespaceFirewall(ns netns.NsHandle, cfg NSConfig) error {
	cfg = normalizeNSConfig(cfg)

	for _, port := range cfg.OpenPorts {
		if port < 1 || port > 65535 {
			return fmt.Errorf("invalid open port %d", port)
		}
	}

	conn, err := newNamespaceFirewallConn(ns)
	if err != nil {
		return fmt.Errorf("open nftables connection in %s: %w", cfg.Name, err)
	}
	if err := configureNamespaceFirewallWithConn(conn, cfg); err != nil {
		return fmt.Errorf("install nftables rules in %s: %w", cfg.Name, err)
	}

	return nil
}
