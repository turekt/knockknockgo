package fwrule

import (
	"bytes"
	"fmt"
	"net"

	"github.com/google/nftables"
	"github.com/google/nftables/binaryutil"
	"github.com/google/nftables/expr"
	"golang.org/x/sys/unix"
)

type NftFWRule struct {
	conn  *nftables.Conn
	table *nftables.Table
	chain *nftables.Chain
	rule  *nftables.Rule
	src   net.IP
	dpt   uint16
}

func newNftFWRule(src net.IP, dpt uint16) *NftFWRule {
	n := &NftFWRule{
		src: src,
		dpt: dpt,
	}
	n.conn = &nftables.Conn{}
	tbl := &nftables.Table{
		Name:   "filter",
		Family: nftables.TableFamilyINet,
	}
	policyDrop := nftables.ChainPolicyDrop
	chn := &nftables.Chain{
		Name:     "input",
		Hooknum:  nftables.ChainHookInput,
		Table:    tbl,
		Priority: 0,
		Type:     nftables.ChainTypeFilter,
		Policy:   &policyDrop,
	}
	n.table = n.conn.AddTable(tbl)
	n.chain = n.conn.AddChain(chn)
	n.conn.Flush()
	return n
}

func (n *NftFWRule) Apply() error {
	n.rule = n.conn.InsertRule(n.nftAcceptInfoRule())
	return n.conn.Flush()
}

func (n *NftFWRule) Drop() error {
	if n.rule == nil {
		return nil
	}

	rules, err := n.conn.GetRule(n.table, n.chain)
	if err != nil {
		return err
	}

	for _, rule := range rules {
		if n.ruleMatches(rule) {
			err := n.conn.DelRule(&nftables.Rule{
				Table:  n.table,
				Chain:  n.chain,
				Handle: rule.Handle,
			})
			if err != nil {
				return err
			}
			return n.conn.Flush()
		}
	}

	return fmt.Errorf("nft rule not found in table %s chain %s", n.table.Name, n.chain.Name)
}

func (n *NftFWRule) ipInfo() (uint32, uint32, []byte) {
	if n.src.To4() != nil {
		return 4, 12, []byte(n.src.To4())
	} else {
		return 16, 8, []byte(n.src.To16())
	}
}

func (n *NftFWRule) nftAcceptInfoRule() *nftables.Rule {
	// nft insert rule inet filter input ip saddr SADDR tcp dport DPORT accept
	addrLen, ipOffset, baddr := n.ipInfo()
	return &nftables.Rule{
		Table: n.table,
		Chain: n.chain,
		Exprs: []expr.Any{
			&expr.Payload{
				DestRegister: 1,
				Base:         expr.PayloadBaseNetworkHeader,
				Offset:       ipOffset,
				Len:          uint32(addrLen),
			},
			&expr.Cmp{
				Op:       expr.CmpOpEq,
				Register: 1,
				Data:     baddr,
			},
			&expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 1},
			&expr.Cmp{
				Op:       expr.CmpOpEq,
				Register: 1,
				Data:     []byte{unix.IPPROTO_TCP},
			},
			&expr.Payload{
				DestRegister: 1,
				Base:         expr.PayloadBaseTransportHeader,
				Offset:       2,
				Len:          2,
			},
			&expr.Cmp{
				Op:       expr.CmpOpEq,
				Register: 1,
				Data:     binaryutil.BigEndian.PutUint16(n.dpt),
			},
			&expr.Verdict{
				Kind: expr.VerdictAccept,
			},
		},
	}
}

func (n *NftFWRule) ruleMatches(r *nftables.Rule) bool {
	if len(r.Exprs) != len(n.rule.Exprs) {
		return false
	}

	for i, ex := range r.Exprs {
		exm, _ := expr.Marshal(ex)
		nrm, _ := expr.Marshal(n.rule.Exprs[i])
		if !bytes.Equal(exm, nrm) {
			return false
		}
	}

	return true
}
