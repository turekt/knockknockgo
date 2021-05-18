#!/bin/sh

rm -rf /opt/kkgo
systemctl stop kkd.service
systemctl disable kkd.service
rm -rf /etc/systemd/system/kkd.service
rm -rf /usr/lib/systemd/system/kkd.service
systemctl daemon-reload
systemctl reset-failed
systemctl status kkd.service