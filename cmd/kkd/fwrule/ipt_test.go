package fwrule

// sudo -E /usr/local/go/bin/go test ./...

import (
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"testing"
)

const (
	testIptIP   = "10.11.12.13"
	testIptPort = "1234"
)

var ipt *IptFWRule

func init() {
	portInt, _ := strconv.Atoi(testIptPort)
	ipt = newIptFWRule(net.ParseIP(testIptIP), uint16(portInt))
}

func TestIptApply(t *testing.T) {
	rootCheck(t)

	ipt.Apply()
	success := false

	for _, rule := range strings.Split(iptablesList(t), "\n") {
		if checkIptRuleOutput(rule, testIptIP, testIptPort) {
			success = true
		}
	}

	if !success {
		t.Fatalf("no rule with %s dpt:%s ACCEPT present", testIptIP, testIptPort)
	}

	ipt.Drop()
}

func TestIptDrop(t *testing.T) {
	rootCheck(t)

	ipt.Apply()
	ipt.Drop()

	for _, rule := range strings.Split(iptablesList(t), "\n") {
		if checkIptRuleOutput(rule, testIptIP, testIptPort) {
			t.Fatalf("found rule %s", rule)
		}
	}
}

func rootCheck(t *testing.T) {
	if os.Geteuid() != 0 {
		// skip test if not root
		t.Skip("firewall test requires root privilege")
	}
}

func iptablesList(t *testing.T) string {
	out, err := exec.Command(iptablesBinPath, "-L", "INPUT").Output()
	if err != nil {
		t.Fatalf("failed iptables -L INPUT %v %s", err, err.(*exec.ExitError).Stderr)
	}
	return string(out)
}

func checkIptRuleOutput(rule, ip, port string) bool {
	return strings.Contains(rule, "ACCEPT") &&
		strings.Contains(rule, "tcp") &&
		strings.Contains(rule, ip) &&
		strings.Contains(rule, "dpt:"+port)
}
