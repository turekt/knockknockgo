#!/bin/sh

PROFILES_DIR="/tmp/knock"

/usr/sbin/nft -f /nftables.conf
/usr/sbin/ulogd -d
/kkd gen -profiles "${PROFILES_DIR}" -port 4444
/usr/sbin/xinetd
/kkd run -profiles "${PROFILES_DIR}" -fw nft -kernlog /var/log/ulogd_syslogemu.log