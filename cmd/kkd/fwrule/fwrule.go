package fwrule

import "net"

const (
	IptFWRuleType FWRuleType = iota
	NftFWRuleType
)

type FWRuleType int

type FWRule interface {
	Apply() error
	Drop() error
}

func New(fwt FWRuleType, src net.IP, dpt uint16) FWRule {
	switch fwt {
	case NftFWRuleType:
		return newNftFWRule(src, dpt)
	default:
		return newIptFWRule(src, dpt)
	}
}
