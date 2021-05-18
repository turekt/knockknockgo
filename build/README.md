# Testing knockknockgo with Docker

Both iptables and nftables Dockerfile is provided in order to test knockknockgo via Docker.

To easily build and/or run the Docker containers you can use `make`:
```sh
# To build both containers
$ make
# To build only nftables container
$ make nft
# To build and immediately run the nftables container
$ make nft-run
# To build only iptables container
$ make ipt
# To build and immediately run the iptables container
$ make ipt-run
```

Interaction with Docker most probably requires root privilege. In order to successfully make, initial build of the binaries in `bin/` must be made.

## Docker container

Both nftables and iptables containers are the same internally, except they are using a different firewall type/command to create rules. The container is running `/bin/sh` as root which listens on port 4444. Any interaction with the port is blocked by the firewall when container is started. In the background `ulogd` service is started and running in order to redirect firewall logs to `/var/log/ulogd.log` (there is no kernel inside the container, so there will be no writing to `/var/log/kern.log`, right?).

When both services are started, `kkd` will execute a `gen` command to generate a profile for port 4444, log the config transfer command to stdout and start as main process which monitors the `/var/log/ulogd.log` for events and reads incoming firewall logs. On successful knock, the Docker container port 4444 will be available to the host machine.

### Example test with nftables

In the server side terminal execute `make nft-run`, example:
```
$ sudo make nft-run
[sudo] password for t: 
cp ../bin/kk ./kk
cp ../bin/kkd ./kkd
docker build -t nft-kkgo -f nftables/Dockerfile .
Sending build context to Docker daemon  9.504MB
Step 1/11 : FROM ubuntu
 ---> 7e0aa2d69a15
Step 2/11 : RUN apt-get update && apt-get install -y nftables ulogd2 xinetd lib32z1
 ---> Using cache
 ---> debd62b978b0
Step 3/11 : COPY kk /
 ---> Using cache
 ---> 7eada9dcbd5b
Step 4/11 : COPY kkd /
 ---> 4c6f52d3f1fe
Step 5/11 : COPY nftables/nftables.conf /
 ---> 09b49939614b
Step 6/11 : COPY nftables/ulogd.conf /etc/ulogd.conf
 ---> b653cc0f3d1e
Step 7/11 : COPY nftables/start.sh /
 ---> 0fdb2e4b5f27
Step 8/11 : RUN chmod +x /start.sh
 ---> Running in a5b63b5b2404
Removing intermediate container a5b63b5b2404
 ---> 0005de48f4e9
Step 9/11 : RUN echo "Connection blocked" > /etc/banner_fail
 ---> Running in dc2e94eae5b5
Removing intermediate container dc2e94eae5b5
 ---> 657acf1a41ec
Step 10/11 : COPY nftables/cat.xinetd /etc/xinetd.d/cat
 ---> 5b06aae35600
Step 11/11 : CMD ["/start.sh"]
 ---> Running in e7693e568812
Removing intermediate container e7693e568812
 ---> fcc2a2d8f2bc
Successfully built fcc2a2d8f2bc
Successfully tagged nft-kkgo:latest
docker run -v /lib/modules:/lib/modules --cap-add NET_ADMIN -it nft-kkgo
execute this on client side:
echo 'ewogICJrZXkiOiAiUVRRdkd6YnF5dTVtelhtQmhlc0xHRzVxVTR4N3FqZ3lyaTlsOTI2Si8vYz0iLAogICJuc2FsdCI6ICJudXd5U0RxTFdJT2RhZGllVjlJS3AzdDhDWEZOZDR3Uk4zQmxiZ3k5MkhJPSIsCiAgImNvdW50ZXIiOiAxLAogICJjaXBoZXIiOiAwLAogICJjb25ud2luIjogMzAwCn0=' | base64 -d > /tmp/knock/4444.json
```

Server side will provide with the configuration for the port 4444. Docker container should be accessible on `172.17.0.2`, therefore we execute from host:
```
$ mkdir -p /tmp/knock
$ echo 'ewogICJrZXkiOiAiUVRRdkd6YnF5dTVtelhtQmhlc0xHRzVxVTR4N3FqZ3lyaTlsOTI2Si8vYz0iLAogICJuc2FsdCI6ICJudXd5U0RxTFdJT2RhZGllVjlJS3AzdDhDWEZOZDR3Uk4zQmxiZ3k5MkhJPSIsCiAgImNvdW50ZXIiOiAxLAogICJjaXBoZXIiOiAwLAogICJjb25ud2luIjogMzAwCn0=' | base64 -d > /tmp/knock/4444.json
$ nc 172.17.0.2 4444
Ncat: Connection refused.
$ sudo ./kk -profiles /tmp/knock 172.17.0.2 4444
[sudo] password for : 
2021/05/17 23:33:33 knocked 172.17.0.2 on port 4444
$ nc 172.17.0.2 4444
id
uid=0(root) gid=0(root) groups=0(root)
```

As client makes requests, server side will log events on screen. Access will be revoked after number of seconds specified by `connwin` parameter (default 300). Recordings are available in the `assets/` folder.