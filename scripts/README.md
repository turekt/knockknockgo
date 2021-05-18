# Server side installation scripts

These shell scripts can be used to quickly deploy knockknockgo on a server. **Scripts assume that the git structure was not changed and that initial build of the code was already made with `make`.**

To install knockknockgo daemon use `INSTALL.sh` (requires root privilege):
```
$ ./INSTALL.sh 
[Unit]
Description=Unit for knockknockgo systemd

[Service]
ExecStart=/opt/kkgo/kkd run -profiles /opt/kkgo/profiles -fw nft -kernlog /var/log/kern.log

[Install]
● kkd.service - Unit for knockknockgo systemd
     Loaded: loaded (/etc/systemd/system/kkd.service; disabled; vendor preset: enabled)
     Active: active (running) since Mon 2021-05-17 23:13:08 CEST; 8ms ago
   Main PID: 62783 (kkd)
      Tasks: 7 (limit: 18884)
     Memory: 4.7M
        CPU: 4ms
     CGroup: /system.slice/kkd.service
             └─62783 /opt/kkgo/kkd run -profiles /opt/kkgo/profiles -fw nft -kernlog /var/log/kern.log

May 17 23:13:08 vm systemd[1]: Started Unit for knockknockgo systemd.
```

After installation, knockknockgo can be removed with `UNINSTALL.sh` which executes `systemctl status kkd.service` after uninstall for uninstall verification (requires root privilege):
```
$ sudo ./UNINSTALL.sh 
Unit kkd.service could not be found.
```