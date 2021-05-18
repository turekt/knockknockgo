# docker build -t nft-kkgo .
# docker run -it --cap-add=NET_ADMIN nft-kkgo
FROM ubuntu

RUN apt-get update && apt-get install -y nftables ulogd2 xinetd lib32z1

COPY kk /
COPY kkd /
COPY nftables/nftables.conf /
COPY nftables/ulogd.conf /etc/ulogd.conf
COPY nftables/start.sh /
RUN chmod +x /start.sh
RUN echo "Connection blocked" > /etc/banner_fail
COPY nftables/cat.xinetd /etc/xinetd.d/cat

CMD ["/start.sh"]