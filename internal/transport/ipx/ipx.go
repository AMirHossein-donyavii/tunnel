// Package ipx is the extension point for the protocol-mimicry transport
// (ICMP / IPIP / GRE / OSPF-style). These are L3 transports that pair with a
// TUN device and the tun_ip/mtu config fields. Until implemented, the "ipx"
// name is served by the experimental placeholder in the parent transport
// package.
//
// To implement: open raw sockets (requires CAP_NET_RAW), encode link frames
// into the chosen carrier protocol, register a Transport, and blank-import it
// in cmd/et-core/main.go.
package ipx
