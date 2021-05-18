package fwrule

import (
	"fmt"
	"net"
	"os/exec"
	"strings"
)

const (
	iptablesBinPath  = "/sbin/iptables"
	ip6tablesBinPath = "/sbin/ip6tables"
)

type IptFWRule struct {
	src  net.IP
	dpt  uint16
	desc []string
}

func newIptFWRule(src net.IP, dpt uint16) *IptFWRule {
	d := fmt.Sprintf("INPUT -m state --state NEW -p tcp -s %s --dport %d -j ACCEPT", src.String(), dpt)
	return &IptFWRule{src, dpt, strings.Split(d, " ")}
}

func (p *IptFWRule) Apply() error {
	return p.execute("-I")
}

func (p *IptFWRule) Drop() error {
	return p.execute("-D")
}

func (p *IptFWRule) execute(opFlag string) error {
	cmd := exec.Command(p.deduceBinPath(), append([]string{opFlag}, p.desc...)...)
	if err := cmd.Run(); err != nil {
		return err
	}
	return nil
}

func (p *IptFWRule) deduceBinPath() string {
	if p.src.To4() != nil {
		return iptablesBinPath
	} else {
		return ip6tablesBinPath
	}
}
