package main

import (
	"flag"
	"log"
	"net"
	"os"
	"strconv"
	"syscall"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/routing"
	"golang.org/x/net/ipv4"
	"golang.org/x/sys/unix"

	"github.com/turekt/knockknockgo/pkg/kcrypto"
	"github.com/turekt/knockknockgo/pkg/kdata"
	"github.com/turekt/knockknockgo/pkg/kprofile"
)

type portKnocker struct {
	kprofile.KnockProfile
	src    net.IP
	dst    net.IP
	port16 uint16
	opts   gopacket.SerializeOptions
	buf    gopacket.SerializeBuffer
}

func newPortKnocker(ip net.IP, port uint16) (*portKnocker, error) {
	pk := &portKnocker{
		dst:    ip,
		port16: port,
		opts: gopacket.SerializeOptions{
			FixLengths:       true,
			ComputeChecksums: true,
		},
		buf: gopacket.NewSerializeBuffer(),
	}

	routing.New()
	router, err := routing.New()
	if err != nil {
		return nil, err
	}

	_, _, pk.src, err = router.Route(ip)
	return pk, err
}

func (pk *portKnocker) calculateData() (*kdata.KnockDataEntry, error) {
	kcipher, err := kcrypto.New(pk.Cipher, pk.Key, pk.NonceSalt)
	if err != nil {
		return nil, err
	}

	ctext, err := kcipher.Encrypt(pk.port16, pk.NonceCounter)
	if err != nil {
		return nil, err
	}

	return kdata.FromCipherText(ctext), nil
}

func (pk *portKnocker) knock4() error {
	kde, err := pk.calculateData()
	if err != nil {
		return err
	}
	kde.Dpt = pk.port16

	ip4 := layers.IPv4{
		SrcIP:    pk.src,
		DstIP:    pk.dst,
		Version:  4,
		TTL:      64,
		Protocol: layers.IPProtocolTCP,
		Id:       uint16(kde.Nonce),
	}
	tcp := layers.TCP{
		SrcPort: layers.TCPPort(kde.Spt),
		DstPort: layers.TCPPort(kde.Dpt),
		SYN:     true,
		Ack:     kde.Ack,
		Seq:     kde.Seq,
		Window:  kde.Window,
	}
	tcp.SetNetworkLayerForChecksum(&ip4)

	if err := ip4.SerializeTo(pk.buf, pk.opts); err != nil {
		return err
	}
	ipHeader, err := ipv4.ParseHeader(pk.buf.Bytes())
	if err != nil {
		return err
	}

	err = gopacket.SerializeLayers(pk.buf, pk.opts, &tcp)
	if err != nil {
		return err
	}

	packetConn, err := net.ListenPacket("ip4:tcp", "0.0.0.0")
	if err != nil {
		return err
	}
	rawConn, err := ipv4.NewRawConn(packetConn)
	if err != nil {
		return err
	}

	return rawConn.WriteTo(ipHeader, pk.buf.Bytes(), nil)
}

func (pk *portKnocker) knock6() error {
	kde, err := pk.calculateData()
	if err != nil {
		return err
	}
	kde.Dpt = pk.port16

	ip6 := layers.IPv6{
		SrcIP:      pk.src,
		DstIP:      pk.dst,
		Version:    6,
		NextHeader: 6,
		HopLimit:   64,
		Length:     60,
		FlowLabel:  uint32(kde.Nonce),
	}
	tcp := layers.TCP{
		SrcPort: layers.TCPPort(kde.Spt),
		DstPort: layers.TCPPort(kde.Dpt),
		SYN:     true,
		Ack:     kde.Ack,
		Seq:     kde.Seq,
		Window:  kde.Window,
	}
	tcp.SetNetworkLayerForChecksum(&ip6)

	err = gopacket.SerializeLayers(pk.buf, pk.opts, &ip6, &tcp)
	if err != nil {
		return err
	}

	fd, err := unix.Socket(syscall.AF_INET6, syscall.SOCK_RAW, syscall.IPPROTO_TCP)
	if err != nil {
		return err
	}

	err = unix.SetsockoptInt(int(fd), unix.IPPROTO_IPV6, unix.IPV6_AUTOFLOWLABEL, 0)
	if err != nil {
		log.Fatalf("failed to configure auto_flowlabel %v", os.NewSyscallError("setsockopt", err))
	}

	err = unix.SetsockoptInt(int(fd), unix.IPPROTO_IPV6, unix.IPV6_HDRINCL, 1)
	if err != nil {
		log.Fatalf("failed to configure hdrincl %v", os.NewSyscallError("setsockopt", err))
	}

	err = unix.Sendto(fd, pk.buf.Bytes(), 0, &unix.SockaddrInet6{})
	if err != nil {
		log.Fatalf("failed to sendto %v", os.NewSyscallError("setsockopt", err))
	}

	unix.Close(fd)
	return nil
}

func main() {
	if os.Geteuid() != 0 {
		log.Fatalln("this program must be run as root")
	}

	profilesDir := flag.String("profiles", kprofile.KnockProfilesDir, "Location where profiles are stored")
	flag.Parse()
	host := flag.Arg(0)
	port := flag.Arg(1)

	if host == "" || port == "" {
		log.Fatalf("usage: %s (ip) (port)\n", os.Args[0])
	}

	portNum, err := strconv.Atoi(port)
	if err != nil || portNum < 0 || portNum > 0xffff {
		log.Fatalf("bad port: %s\n", port)
	}
	portNum16 := uint16(portNum)

	dstIP := net.ParseIP(host)
	if dstIP == nil {
		addrs, err := net.LookupHost(host)
		if err != nil || len(addrs) == 0 {
			log.Fatalf("bad ip: %q\n", host)
		}
		dstIP = net.ParseIP(addrs[0])
	}

	pk, err := newPortKnocker(dstIP, portNum16)
	if err != nil {
		log.Fatalf("error creating port knocker %v", err)
	}

	kp, err := kprofile.Deserialize(portNum16, *profilesDir)
	if err != nil {
		log.Fatalf("error deserializing profile for port %s %v", port, err)
	}
	pk.KnockProfile = *kp

	if dstIP.To4() != nil {
		if err := pk.knock4(); err != nil {
			log.Fatalf("knock failed %v", err)
		}
	} else {
		if err := pk.knock6(); err != nil {
			log.Fatalf("knock failed %v", err)
		}
	}

	pk.NonceCounter++
	pk.Serialize(*profilesDir)
	log.Printf("knocked %s on port %s", host, port)
}
