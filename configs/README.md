# Configurations

These files are sample files which present minimal configuration needed in order for knockknockgo to work.

## Firewall configurations

Depending on your firewall choice, there are two available default configurations.

The default iptables configuration is an `iptables-conf.sh` shell script and can be execute prior running `kkd` on a server.

The default nftables configuration is an `nftables.conf` file which can be loaded with `nft` with:
```sh
nft -f ./nftables.conf
```

Both requires root privilege.

## Systemd unit file

Default systemd unit file is provided and can be loaded manually with:
```sh
# Depending on firewall choice
# TYPE=nft
# or
# TYPE=ipt
sed "s/FWTYPE/${TYPE}/" ./kkd.service | tee /etc/systemd/system/kkd.service
systemctl daemon-reload
systemctl start kkd.service
```
or just use the `INSTALL.sh` script in the `scripts/` folder.

Unit loading requires root privilege.