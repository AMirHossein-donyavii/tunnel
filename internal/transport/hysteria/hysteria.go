// Package hysteria is the extension point for the QUIC/UDP transport
// (low-latency, congestion-controlled, reverse+direct). Until implemented, the
// "hysteria" name is served by the experimental placeholder in the parent
// transport package.
//
// To implement: wrap a QUIC stream as net.Conn, register a Transport, and
// blank-import it in cmd/et-core/main.go. A QUIC library (e.g. quic-go) would
// be the one heavier dependency; keep it behind a build tag to preserve the
// minimal default binary.
package hysteria
