// Package ssh is the extension point for the SSH camouflage transport
// (TCP/22, SSH-like framing). Until implemented, the "ssh" name is served by
// the experimental placeholder registered in the parent transport package.
//
// To implement: provide a Transport that dials/accepts on 22 and emulates SSH
// banner/framing, then register it and blank-import it in cmd/et-core/main.go.
package ssh
