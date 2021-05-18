# Dropping root privileges

As in the original knockknock, the Go refresh drops needed root privilege. Root is needed in order to:
- monitor `/var/log/kern.log` for firewall logs
- handle firewall rules on successful client verification and connection window expiry

The initial service is started as root but the after executing two separate goroutines for monitoring and firewall handling, the root privileges are dropped. The actual privileges used to run the `kkd` is easily verified with `ps`:
```sh
$ sudo ./kkd run &
[1] 68249
$ ps uax | grep kkd
root       68249  0.0  0.0  10592  4916 pts/0    S    00:11   0:00 sudo ./kkd run
nobody     68250  0.0  0.0 1151092 10280 pts/0   Sl   00:11   0:00 ./kkd run
```

The privilege drop feature works well in Docker container too:
```sh
$ sudo docker ps
CONTAINER ID   IMAGE      COMMAND       CREATED         STATUS         PORTS     NAMES
2b200b472533   nft-kkgo   "/start.sh"   9 seconds ago   Up 8 seconds             goofy_stonebraker
$ sudo docker exec -ti 2b200b472533 sh
# ps uax
USER         PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND
root           1  0.1  0.0   2616   592 pts/0    Ss+  22:11   0:00 /bin/sh /start.sh
root           9  0.0  0.0   5640  2332 ?        Ss   22:11   0:00 /usr/sbin/ulogd -d
root          17  0.0  0.0  12028  2120 ?        Ss   22:11   0:00 /usr/sbin/xinetd
nobody        18  0.0  0.0 1297088 10344 pts/0   Sl+  22:11   0:00 /kkd run -profiles /tmp/knock -fw nft 
root          27  1.0  0.0   2616   604 pts/1    Ss   22:11   0:00 sh
root          33  0.0  0.0   5904  2844 pts/1    R+   22:12   0:00 ps uax
```