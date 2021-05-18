# Libraries used in knockknockgo

The philosophy of knockknockgo is to not stitch the solution with multiple libraries and bloat it with unnecessary functionality and dependencies that can get deprecated, etc. The idea was to use as little libraries as possible for knockknockgo and rely on standard Go libraries. Every dependency was carefully thought through and enrolled only because it was really necessary.

Therefore, knockknockgo directly depends only on:
- `golang.org/x/crypto` - ChaCha20-Poly1305 implementation
- `golang.org/x/net` - address parsing, packet creation and packet parsing
- `golang.org/x/sys` - unix package for dropping privileges and IPv6 raw socket sending
- `github.com/google/gopacket` - for client side packet creation
- `github.com/google/nftables` - for interaction with nftables through netfilter