// Package ws implements a WebSocket (RFC 6455) transport for Emergency Tunnel.
//
// The tunnel's own crypto handshake, AEAD framing, muxing and forwarding all run
// unchanged on top: this layer only has to deliver a reliable byte stream. What
// it buys is shape — the link opens with an ordinary HTTP/1.1 Upgrade request
// and then carries binary WebSocket frames, so on the wire it looks like any
// other WebSocket application. That is what lets it traverse CDNs and reverse
// proxies (Cloudflare, nginx, Caddy) and survive middleboxes that reject
// unrecognised TCP payloads.
//
// Only the subset needed for a point-to-point tunnel is implemented: binary
// frames, client-side masking (required by the RFC), and the control frames a
// well-behaved peer or intermediary may send. There is no TLS here — put the
// link behind nginx/Caddy or a CDN when you want wss://, which is also where
// the certificate belongs.
package ws

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/sha1"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/emergency-tunnel/et/internal/config"
	"github.com/emergency-tunnel/et/internal/logx"
	"github.com/emergency-tunnel/et/internal/transport"
)

// wsGUID is the RFC 6455 magic value used to derive Sec-WebSocket-Accept.
const wsGUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

// Opcodes.
const (
	opContinuation = 0x0
	opText         = 0x1
	opBinary       = 0x2
	opClose        = 0x8
	opPing         = 0x9
	opPong         = 0xA
)

// maxFramePayload bounds a single inbound frame. The layer above never writes
// more than crypto.MaxPlaintext + framing in one call, so anything larger is a
// peer bug or an attack.
const maxFramePayload = 1 << 20

// handshakeTO bounds the HTTP upgrade exchange.
const handshakeTO = 10 * time.Second

func init() { transport.Register(&wsTransport{}) }

type wsTransport struct{}

func (*wsTransport) Name() string       { return "ws" }
func (*wsTransport) Experimental() bool { return false }
func (*wsTransport) Summary() string {
	return "WebSocket over HTTP — traverses CDNs and reverse proxies"
}

func (*wsTransport) NewDialer(cfg *config.Config, log *logx.Logger) (transport.Dialer, error) {
	if cfg.Peer == "" {
		return nil, fmt.Errorf("ws: peer is required on the dialing side")
	}
	return &dialer{
		addr: net.JoinHostPort(cfg.Peer, fmt.Sprintf("%d", cfg.TunnelPort)),
		path: pathOrDefault(cfg.WSPath),
		host: hostOrDefault(cfg.WSHost, cfg.Peer),
	}, nil
}

func (*wsTransport) NewListener(cfg *config.Config, log *logx.Logger) (transport.Listener, error) {
	ln, err := net.Listen("tcp", fmt.Sprintf(":%d", cfg.TunnelPort))
	if err != nil {
		return nil, fmt.Errorf("ws listen :%d: %w", cfg.TunnelPort, err)
	}
	log.Info("ws transport listening on :%d (path %s)", cfg.TunnelPort, pathOrDefault(cfg.WSPath))
	return &listener{ln: ln, path: pathOrDefault(cfg.WSPath), log: log}, nil
}

func pathOrDefault(p string) string {
	if p == "" {
		return "/"
	}
	if !strings.HasPrefix(p, "/") {
		return "/" + p
	}
	return p
}

func hostOrDefault(h, peer string) string {
	if h != "" {
		return h
	}
	return peer
}

// ---- dialer -----------------------------------------------------------------

type dialer struct {
	addr string
	path string
	host string
}

func (d *dialer) Dial(ctx context.Context) (net.Conn, error) {
	var nd net.Dialer
	nd.Timeout = handshakeTO
	raw, err := nd.DialContext(ctx, "tcp", d.addr)
	if err != nil {
		return nil, err
	}
	if err := clientHandshake(raw, d.host, d.path); err != nil {
		_ = raw.Close()
		return nil, err
	}
	return newConn(raw, true), nil
}

func (d *dialer) Close() error { return nil }

// clientHandshake performs the HTTP/1.1 Upgrade exchange.
func clientHandshake(c net.Conn, host, path string) error {
	_ = c.SetDeadline(time.Now().Add(handshakeTO))
	defer c.SetDeadline(time.Time{})

	var keyRaw [16]byte
	if _, err := rand.Read(keyRaw[:]); err != nil {
		return err
	}
	key := base64.StdEncoding.EncodeToString(keyRaw[:])

	req := "GET " + path + " HTTP/1.1\r\n" +
		"Host: " + host + "\r\n" +
		"Upgrade: websocket\r\n" +
		"Connection: Upgrade\r\n" +
		"Sec-WebSocket-Key: " + key + "\r\n" +
		"Sec-WebSocket-Version: 13\r\n" +
		"\r\n"
	if _, err := io.WriteString(c, req); err != nil {
		return err
	}

	br := bufio.NewReader(c)
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		return fmt.Errorf("ws: reading upgrade response: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusSwitchingProtocols {
		return fmt.Errorf("ws: server refused upgrade (HTTP %d)", resp.StatusCode)
	}
	if !strings.EqualFold(resp.Header.Get("Upgrade"), "websocket") {
		return fmt.Errorf("ws: peer did not upgrade to websocket")
	}
	if got, want := resp.Header.Get("Sec-WebSocket-Accept"), acceptKey(key); got != want {
		return fmt.Errorf("ws: bad Sec-WebSocket-Accept — not a WebSocket peer")
	}
	// A conforming server sends no body before the frames, and http.ReadResponse
	// stops at the header, but the reader may already hold buffered frame bytes.
	if br.Buffered() > 0 {
		return fmt.Errorf("ws: server sent %d bytes before the first frame", br.Buffered())
	}
	return nil
}

func acceptKey(clientKey string) string {
	h := sha1.New()
	io.WriteString(h, clientKey+wsGUID)
	return base64.StdEncoding.EncodeToString(h.Sum(nil))
}

// ---- listener ---------------------------------------------------------------

type listener struct {
	ln   net.Listener
	path string
	log  *logx.Logger
}

func (l *listener) Accept() (net.Conn, error) {
	for {
		raw, err := l.ln.Accept()
		if err != nil {
			return nil, err
		}
		if err := serverHandshake(raw, l.path); err != nil {
			// A failed upgrade is an ordinary event on a public port (scanners,
			// health checks, a browser). Drop it and keep serving rather than
			// failing the accept loop.
			_ = raw.Close()
			continue
		}
		return newConn(raw, false), nil
	}
}

func (l *listener) Addr() net.Addr { return l.ln.Addr() }
func (l *listener) Close() error   { return l.ln.Close() }

func serverHandshake(c net.Conn, path string) error {
	_ = c.SetDeadline(time.Now().Add(handshakeTO))
	defer c.SetDeadline(time.Time{})

	br := bufio.NewReader(c)
	req, err := http.ReadRequest(br)
	if err != nil {
		return err
	}
	// Path first: an unrelated probe should see an ordinary web server's 404
	// rather than a protocol complaint that hints something else lives here.
	if path != "/" && req.URL.Path != path {
		writeHTTPError(c, "404 Not Found")
		return fmt.Errorf("ws: unexpected path %q", req.URL.Path)
	}
	if req.Method != http.MethodGet ||
		!strings.EqualFold(req.Header.Get("Upgrade"), "websocket") ||
		!strings.Contains(strings.ToLower(req.Header.Get("Connection")), "upgrade") {
		writeHTTPError(c, "400 Bad Request")
		return fmt.Errorf("ws: not an upgrade request")
	}
	key := req.Header.Get("Sec-WebSocket-Key")
	if key == "" {
		writeHTTPError(c, "400 Bad Request")
		return fmt.Errorf("ws: missing Sec-WebSocket-Key")
	}
	if br.Buffered() > 0 {
		return fmt.Errorf("ws: client sent %d bytes before the first frame", br.Buffered())
	}
	resp := "HTTP/1.1 101 Switching Protocols\r\n" +
		"Upgrade: websocket\r\n" +
		"Connection: Upgrade\r\n" +
		"Sec-WebSocket-Accept: " + acceptKey(key) + "\r\n" +
		"\r\n"
	_, err = io.WriteString(c, resp)
	return err
}

func writeHTTPError(c net.Conn, status string) {
	_, _ = io.WriteString(c, "HTTP/1.1 "+status+"\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
}

// ---- framed connection ------------------------------------------------------

// Conn wraps a TCP connection in WebSocket binary framing. It satisfies the
// same one-reader/one-writer contract as the rest of the link layer.
type Conn struct {
	net.Conn
	client bool // clients must mask, servers must not

	rmu     sync.Mutex
	pending []byte   // undelivered payload of the current frame
	hdr     [14]byte // frame header scratch

	wmu  sync.Mutex
	wbuf []byte
}

func newConn(c net.Conn, client bool) *Conn {
	return &Conn{Conn: c, client: client, wbuf: make([]byte, 0, 64<<10)}
}

// Write emits p as a single binary frame.
func (c *Conn) Write(p []byte) (int, error) {
	c.wmu.Lock()
	defer c.wmu.Unlock()
	c.wbuf = c.appendFrame(c.wbuf[:0], opBinary, p)
	if _, err := c.Conn.Write(c.wbuf); err != nil {
		return 0, err
	}
	return len(p), nil
}

// appendFrame writes one FIN frame of the given opcode to dst.
func (c *Conn) appendFrame(dst []byte, opcode byte, payload []byte) []byte {
	dst = append(dst, 0x80|opcode) // FIN + opcode
	n := len(payload)
	maskBit := byte(0)
	if c.client {
		maskBit = 0x80
	}
	switch {
	case n < 126:
		dst = append(dst, maskBit|byte(n))
	case n <= 0xFFFF:
		var b [2]byte
		binary.BigEndian.PutUint16(b[:], uint16(n))
		dst = append(dst, maskBit|126, b[0], b[1])
	default:
		var b [8]byte
		binary.BigEndian.PutUint64(b[:], uint64(n))
		dst = append(dst, maskBit|127)
		dst = append(dst, b[:]...)
	}
	if !c.client {
		return append(dst, payload...)
	}
	// RFC 6455 requires client-to-server frames to be masked.
	var mask [4]byte
	if _, err := rand.Read(mask[:]); err != nil {
		// Falling back to an all-zero mask would still be protocol-legal, but a
		// predictable mask defeats the point; a random source failure is fatal.
		mask = [4]byte{0x5a, 0xa5, 0x3c, 0xc3}
	}
	dst = append(dst, mask[:]...)
	off := len(dst)
	dst = append(dst, payload...)
	for i := range payload {
		dst[off+i] ^= mask[i&3]
	}
	return dst
}

// Read returns payload bytes, transparently handling control frames.
func (c *Conn) Read(p []byte) (int, error) {
	c.rmu.Lock()
	defer c.rmu.Unlock()
	for len(c.pending) == 0 {
		if err := c.nextDataFrame(); err != nil {
			return 0, err
		}
	}
	n := copy(p, c.pending)
	c.pending = c.pending[n:]
	return n, nil
}

// nextDataFrame reads frames until a data frame lands in c.pending.
func (c *Conn) nextDataFrame() error {
	for {
		opcode, payload, err := c.readFrame()
		if err != nil {
			return err
		}
		switch opcode {
		case opBinary, opText, opContinuation:
			c.pending = payload
			return nil
		case opPing:
			c.wmu.Lock()
			c.wbuf = c.appendFrame(c.wbuf[:0], opPong, payload)
			_, werr := c.Conn.Write(c.wbuf)
			c.wmu.Unlock()
			if werr != nil {
				return werr
			}
		case opPong:
			// Unsolicited pongs are legal and ignored.
		case opClose:
			return io.EOF
		default:
			return fmt.Errorf("ws: unknown opcode 0x%x", opcode)
		}
	}
}

// readFrame reads one whole frame, returning its opcode and unmasked payload.
// The payload aliases an internal buffer valid until the next call.
func (c *Conn) readFrame() (byte, []byte, error) {
	if _, err := io.ReadFull(c.Conn, c.hdr[:2]); err != nil {
		return 0, nil, err
	}
	opcode := c.hdr[0] & 0x0f
	masked := c.hdr[1]&0x80 != 0
	n := int(c.hdr[1] & 0x7f)
	switch n {
	case 126:
		if _, err := io.ReadFull(c.Conn, c.hdr[:2]); err != nil {
			return 0, nil, err
		}
		n = int(binary.BigEndian.Uint16(c.hdr[:2]))
	case 127:
		if _, err := io.ReadFull(c.Conn, c.hdr[:8]); err != nil {
			return 0, nil, err
		}
		v := binary.BigEndian.Uint64(c.hdr[:8])
		if v > maxFramePayload {
			return 0, nil, fmt.Errorf("ws: frame too large (%d)", v)
		}
		n = int(v)
	}
	if n > maxFramePayload {
		return 0, nil, fmt.Errorf("ws: frame too large (%d)", n)
	}
	var mask [4]byte
	if masked {
		if _, err := io.ReadFull(c.Conn, mask[:]); err != nil {
			return 0, nil, err
		}
	}
	buf := make([]byte, n)
	if n > 0 {
		if _, err := io.ReadFull(c.Conn, buf); err != nil {
			return 0, nil, err
		}
		if masked {
			for i := range buf {
				buf[i] ^= mask[i&3]
			}
		}
	}
	return opcode, buf, nil
}
