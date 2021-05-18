# Creation of custom packets in Go

To easily create custom TCP packets, gopacket is utilized.

There are two different approaches of creating TCP packets depending on the IP protocol being used (v4 or v6).

## IPv4 packet creation and sending

One could theoretically write raw bytes, but gopacket makes the implementation more robust.

Layers are built with gopacket:
```go
ip4 := layers.IPv4{
    SrcIP:    src,
    DstIP:    dst,
    Version:  4,
    TTL:      64,
    Protocol: layers.IPProtocolTCP,
    Id:       uint16(nonce),
}
tcp := layers.TCP{
    SrcPort: layers.TCPPort(spt),
    DstPort: layers.TCPPort(dpt),
    SYN:     true,
    Ack:     ack,
    Seq:     seq,
    Window:  window,
}
tcp.SetNetworkLayerForChecksum(&ip4)
```

The gopacket example code usually sends the packet via `pcap.Handle`. But this does not work with knockknockgo since packets sent via `pcap.Handle` were not registered by the Linux kernel. Not registering packets sent via `pcap.Handle` is an issue since `iptables`/`nftables` will not recognize and log the packet into `/var/log/kern.log`. Therefore, to actually catch the sent packet, Go `net` package must be utilized:
```go
// IP layer serialized to buf
ip4.SerializeTo(buf, opts)
// IP header parsed to ipv4.Header
ipHeader, _ := ipv4.ParseHeader(buf.Bytes())
// Serializes only TCP layer
gopacket.SerializeLayers(buf, opts, &tcp)
// Bind to 0
packetConn, _ := net.ListenPacket("ip4:tcp", "0.0.0.0")
// Init raw packet connection
rawConn, _ := ipv4.NewRawConn(packetConn)
// Send IP header and TCP header bytes as packet
rawConn.WriteTo(ipHeader, buf.Bytes(), nil)
```

The IPv4 header is parsed separately from TCP header since the call to `WriteTo` function expects `ipv4.Header` struct and raw TCP header bytes as separate parameters. The `WriteTo` function is the one that will send the crafted layers as one packet through raw connection.

## IPv6 packet creation and sending

The IPv6 packet creation is similar, if not the same, to IPv4 - only header fields are different. Packet creation still uses gopacket, but sending no longer is possible with `net` package.
```go
ip6 := layers.IPv6{
    SrcIP:     src,
    DstIP:     dst,
    Version:   6,
    FlowLabel: uint32(nonce),
}
tcp := layers.TCP{
    SrcPort: layers.TCPPort(spt),
    DstPort: layers.TCPPort(dpt),
    SYN:     true,
    Ack:     ack,
    Seq:     seq,
    Window:  window,
}
tcp.SetNetworkLayerForChecksum(&ip6)
```

## Problem with net package

Functions provided by the `net` package are different for IPv4 and IPv6. Specifically, the `WriteTo` function no longer cares about the IP header, only expects IP address with TCP header bytes:

```go
// Serialize TCP header bytes to buf
gopacket.SerializeLayers(buf, opts, &tcp)
// Bind to 0
packetConn, _ := net.ListenPacket("ip6:tcp", "::")
// Init raw packet connection
rawConn := ipv6.NewPacketConn(packetConn)
// Write TCP header, no way to specify IPv6 (and cannot specify IPv6+TCP bytes, because IPv6 header is created by WriteTo)
n, _ := rawConn.WriteTo(buf.Bytes(), nil, &net.IPAddr{IP: dst, Zone: ""})
```

Since IPv6 cannot be serialized as part of the packet, there is a need to go much deeper into the low level implementations of the `net` package - but they are all contained in the `internal` package which Go blocks by default when compiling.

So, there is not much else that we can do other than: Linux syscalls.

## Crafting IPv6 header with Go unix package

The gopacket library is still used for crafting packets. The only difference is in initiating raw sockets and sending packet bytes. The gopacket layers are serialized to bytes for later use:
```go
// Both IPv6+TCP headers are serialized
gopacket.SerializeLayers(buf, opts, &ip6, &tcp)
```

The L3 and L4 packet bytes will be put in `buf`. To send the raw bytes via raw socket, we have to make sure to initiate a raw socket with two socket options set:
```go
// Initiate raw socket TCP IPv6
fd, _ := unix.Socket(syscall.AF_INET6, syscall.SOCK_RAW, syscall.IPPROTO_TCP)
// Call setsockopt enable IPV6_HDRINCL
unix.SetsockoptInt(int(fd), unix.IPPROTO_IPV6, unix.IPV6_HDRINCL, 1)
// Call setsockopt disable IPV6_AUTOFLOWLABEL
unix.SetsockoptInt(int(fd), unix.IPPROTO_IPV6, unix.IPV6_AUTOFLOWLABEL, 0)
// Send IPv6+TCP header bytes via raw socket, the IPv6 addr is irrelevant here
unix.Sendto(fd, pk.buf.Bytes(), 0, &unix.SockaddrInet6{})
// Close socket
unix.Close(fd)
```

Lots of things are happening in the above code, here is a breakdown on why things are setup as they are.

### Socket and IPV6_HDRINCL

The TCP IPv6 raw socket that is created is normally used to send custom transport layer packets (i.e. definition of own L4 protocol). This is not sufficient for knockknockgo. In order for knockknockgo to work, we have to set a custom flow label in the IPv6 header. The Linux documentation states an interesting socket option that helps us with the issue:
```
$ man 7 ip
...
IP_HDRINCL (since Linux 2.0)
        If  enabled,  the  user supplies an IP header in front of the user data.  Valid only for SOCK_RAW sockets; see raw(7) for more information.  When this flag is enabled, the values set by IP_OPTIONS, IP_TTL, and IP_TOS are ignored.
...
```

The `IP_HDRINCL` option can be used in Linux to be able to supply an IP header in front of the user data. The only difference is that `IP_HDRINCL` is used for IPv4, to enable custom IPv6 headers `IPV6_HDRINCL` must be specified.

### IPV6_AUTOFLOWLABEL and SendTo

During testing of sending custom IPv6 packet with wireshark, I noticed that the IPv6 header flow label field is always fixed and nowhere near the value I wanted. Further troubleshooting and research revealed the following `/proc/sys/net/ipv6/*` variable:
```
auto_flowlabels - INTEGER
	Automatically generate flow labels based on a flow hash of the
	packet. This allows intermediate devices, such as routers, to
	identify packet flows for mechanisms like Equal Cost Multipath
	Routing (see RFC 6438).
	0: automatic flow labels are completely disabled
	1: automatic flow labels are enabled by default, they can be
	   disabled on a per socket basis using the IPV6_AUTOFLOWLABEL
	   socket option
	2: automatic flow labels are allowed, they may be enabled on a
	   per socket basis using the IPV6_AUTOFLOWLABEL socket option
	3: automatic flow labels are enabled and enforced, they cannot
	   be disabled by the socket option
	Default: 1
```

The documentation says it all. Setting `IPV6_AUTOFLOWLABEL` socket option to `0` enables us to supply custom flow label value. When bytes are sent via the socket, the `SockaddrInet6` is not important since the IPv6 header bytes already contain the IP address of the target host. The raw socket will pick up the appropriate address and send the packet.