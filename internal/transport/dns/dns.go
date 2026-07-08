// Package dns is the extension point for the DNS transport (UDP/53 with a
// reliable, cached tunnel layer). Until implemented, the "dns" name is served
// by the experimental placeholder registered in the parent transport package.
//
// To implement: provide a Transport whose Dial/Accept establish a net.Conn-like
// stream over DNS queries, then call transport.Register(...) from an init() in
// this package and add a blank import in cmd/et-core/main.go. The crypto
// handshake, pooling and forwarding layers work unchanged on top.
package dns
