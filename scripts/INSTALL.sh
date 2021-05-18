#!/bin/sh

TYPE="nft"
if [ $# -gt 0 ] && [ "$1" = "ipt" ]; then
    TYPE="ipt"
fi


mkdir -p /opt/kkgo/profiles
cp ../bin/kkd /opt/kkgo
sed "s/FWTYPE/${TYPE}/" ../configs/kkd.service | tee /etc/systemd/system/kkd.service
systemctl daemon-reload
systemctl start kkd.service
systemctl status kkd.service