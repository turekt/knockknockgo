# docker build -t ipt-kkgo .
# docker run -it --cap-add=NET_ADMIN ipt-kkgo
FROM ubuntu

RUN apt-get update && apt-get install -y iptables ulogd2 xinetd lib32z1

COPY kk /
COPY kkd /
COPY iptables/iptables-conf.sh /
COPY iptables/ulogd.conf /etc/ulogd.conf
COPY iptables/cat.xinetd /etc/xinetd.d/cat
COPY iptables/start.sh /
RUN chmod +x /start.sh
RUN update-alternatives --set ip6tables /usr/sbin/ip6tables-nft
RUN echo "Connection blocked" > /etc/banner_fail

CMD ["/start.sh"]
