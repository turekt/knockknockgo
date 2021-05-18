DOCKER=docker
NFTDOCKER=nft-kkgo
IPTDOCKER=ipt-kkgo

.PHONY: all ipt nft ipt-run nft-run

all: ipt nft

prep:
	cp ../bin/kk ./kk
	cp ../bin/kkd ./kkd

ipt: prep
	$(DOCKER) build -t $(IPTDOCKER) -f iptables/Dockerfile .

nft: prep
	$(DOCKER) build -t $(NFTDOCKER) -f nftables/Dockerfile .

ipt-run: ipt
	$(DOCKER) run -v /lib/modules:/lib/modules --cap-add NET_ADMIN -it $(IPTDOCKER)

nft-run: nft
	$(DOCKER) run -v /lib/modules:/lib/modules --cap-add NET_ADMIN -it $(NFTDOCKER)
