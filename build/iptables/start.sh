#!/bin/sh

PROFILES_DIR="/tmp/knock"

/iptables-conf.sh
/usr/sbin/ulogd -d
/kkd gen -profiles "${PROFILES_DIR}" -port 4444
/usr/sbin/xinetd
/kkd run -profiles "${PROFILES_DIR}" -fw ipt -kernlog /var/log/ulogd_syslogemu.log