#!/bin/sh

for IPTABLES in "/sbin/iptables" "/sbin/ip6tables"; do
	$IPTABLES -A INPUT -m state --state RELATED,ESTABLISHED -j ACCEPT
	$IPTABLES -A OUTPUT -m state --state NEW,RELATED,ESTABLISHED -j ACCEPT
	$IPTABLES -A OUTPUT -j ACCEPT
	$IPTABLES -A FORWARD -j REJECT
	$IPTABLES -N REJECTLOG
	$IPTABLES -A REJECTLOG -j NFLOG --nflog-prefix "REJECT " --nflog-group 0
	$IPTABLES -A REJECTLOG -p tcp -j REJECT --reject-with tcp-reset
	$IPTABLES -A REJECTLOG -j REJECT
	$IPTABLES -A INPUT -j REJECTLOG
	$IPTABLES -A INPUT -j REJECT
done
