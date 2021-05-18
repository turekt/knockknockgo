package fwrule

// sudo -E /usr/local/go/bin/go test ./...

import (
	"fmt"
	"math/big"
	"net"
	"os/exec"
	"strconv"
	"strings"
	"testing"
)

const (
	testNftIP   = "192.168.1.1"
	testNftPort = "4444"
)

var nft *NftFWRule

func init() {
	portInt, _ := strconv.Atoi(testNftPort)
	nft = newNftFWRule(net.ParseIP(testNftIP), uint16(portInt))
}

func TestNftCreate(t *testing.T) {
	rootCheck(t)

	success := false
	for _, rule := range strings.Split(nftablesList(t), "\x0a\x09") {
		if strings.Contains(rule, "ct state established,related accept") {
			success = true
		}
	}
	if !success {
		t.Fatal("no ct state rule found")
	}
}

func TestNftApply(t *testing.T) {
	rootCheck(t)
	nft.Apply()

	success := false
	for _, rule := range strings.Split(nftablesList(t), "\x0a\x09") {
		if checkNftRuleOutput(rule, testNftIP, testNftPort) {
			success = true
		}
	}

	if !success {
		t.Fatalf("no rule with saddr:%s dpt:%s accept present", testNftIP, testNftPort)
	}

	nft.Drop()
}

func TestNftDrop(t *testing.T) {
	rootCheck(t)
	nft.Apply()
	nft.Drop()

	for _, rule := range strings.Split(nftablesList(t), "\n") {
		if checkNftRuleOutput(rule, testNftIP, testNftPort) {
			t.Fatalf("found rule %s", rule)
		}
	}
}

func nftablesList(t *testing.T) string {
	out, err := exec.Command("nft", "list", "ruleset").Output()
	if err != nil {
		t.Fatalf("failed nft list ruleset %v %s", err, err.(*exec.ExitError).Stderr)
	}
	return string(out)
}

func checkNftRuleOutput(rule, ip, port string) bool {
	netIP := net.ParseIP(ip)
	ipInt := big.NewInt(0)
	var bits uint64
	if netIP.To4() == nil {
		bits = 64
		ipInt.SetBytes(netIP.To16())
	} else {
		bits = 32
		ipInt.SetBytes(netIP.To4())
	}
	expected := fmt.Sprintf("@nh,96,%d %d tcp dport %s accept", bits, ipInt.Uint64(), port)
	return strings.Contains(rule, expected)
}
