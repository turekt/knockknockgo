#!/bin/sh

IPTABLES="/sbin/iptables"
$IPTABLES -A INPUT -m state --state RELATED,ESTABLISHED -j ACCEPT
$IPTABLES -A OUTPUT -m state --state NEW,RELATED,ESTABLISHED -j ACCEPT
$IPTABLES -A OUTPUT -j ACCEPT
$IPTABLES -A FORWARD -j REJECT
$IPTABLES -N REJECTLOG
$IPTABLES -A REJECTLOG -j LOG --log-prefix "REJECT " --log-level debug --log-tcp-sequence --log-tcp-options --log-ip-options
$IPTABLES -A REJECTLOG -p tcp -j REJECT --reject-with tcp-reset
$IPTABLES -A REJECTLOG -j REJECT
$IPTABLES -A INPUT -j REJECTLOG
$IPTABLES -A INPUT -j REJECT