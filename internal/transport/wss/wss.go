// Package wss carries the tunnel inside ordinary HTTPS.
//
// The WebSocket transport already looks like web traffic to anything reading
// HTTP, but on the wire it is plaintext HTTP: the upgrade, the path and the
// headers are all visible, and a Go TLS client — had one been used — announces
// itself with a ClientHello no browser produces. Either is enough to tell this
// apart from a person loading a website.
//
// This wraps the same WebSocket framing in TLS, and dials with a real Chrome
// fingerprint rather than Go's. Combined with the decoy page the WebSocket
// listener serves to anything that is not a tunnel connection, a probe finds a
// web server with a browser-shaped visitor — which is what survives filtering
// that blocks the unfamiliar.
//
// The TLS here is camouflage, not the security boundary: the tunnel's own
// handshake still authenticates and encrypts everything inside it, exactly as
// it does on every other transport. That is why a self-signed certificate is
// enough for the tunnel to work, and why the client does not verify one by
// default. Point tls_sni at a real hostname with a real certificate and set
// tls_verify = true to make it verify, which is worth doing when the address is
// a domain you control — a certificate that validates is one less thing about
// the connection that stands out.
package wss

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"net"
	"os"
	"strings"
	"sync"
	"time"

	utls "github.com/refraction-networking/utls"

	"github.com/emergency-tunnel/et/internal/config"
	"github.com/emergency-tunnel/et/internal/logx"
	"github.com/emergency-tunnel/et/internal/transport"
	"github.com/emergency-tunnel/et/internal/transport/ws"
)

func init() { transport.Register(&wssTransport{}) }

type wssTransport struct{}

func (*wssTransport) Name() string       { return "wss" }
func (*wssTransport) Experimental() bool { return false }
func (*wssTransport) Summary() string {
	return "WebSocket over TLS with a Chrome fingerprint — looks like an HTTPS website"
}

func (*wssTransport) NewDialer(cfg *config.Config, log *logx.Logger) (transport.Dialer, error) {
	if strings.TrimSpace(cfg.Peer) == "" {
		return nil, fmt.Errorf("transport %q: peer is required on the dialing side", "wss")
	}
	sni := strings.TrimSpace(cfg.TLSSNI)
	if sni == "" {
		sni = strings.TrimSpace(cfg.WSHost)
	}
	if sni == "" {
		sni = cfg.Peer
	}
	return &dialer{
		addr:   net.JoinHostPort(cfg.Peer, fmt.Sprintf("%d", cfg.TunnelPort)),
		sni:    sni,
		verify: cfg.TLSVerify,
		inner:  ws.NewClientHandshaker(cfg),
		log:    log,
	}, nil
}

func (*wssTransport) NewListener(cfg *config.Config, log *logx.Logger) (transport.Listener, error) {
	cert, err := CertificateFor(cfg)
	if err != nil {
		return nil, err
	}
	raw, err := net.Listen("tcp", fmt.Sprintf(":%d", cfg.TunnelPort))
	if err != nil {
		return nil, err
	}
	tlsCfg := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
		NextProtos:   []string{"http/1.1"},
	}
	log.Info("wss transport listening on :%d", cfg.TunnelPort)
	return &listener{
		ln:    tls.NewListener(raw, tlsCfg),
		inner: ws.NewServerHandshaker(cfg),
		log:   log,
		ready: make(chan net.Conn, 8),
		fatal: make(chan error, 1),
		done:  make(chan struct{}),
	}, nil
}

// CertificateFor loads the configured certificate, or generates a self-signed
// one. Exported because the QUIC transport needs exactly the same behaviour —
// QUIC is always TLS — and two copies of certificate handling would drift. A generated certificate is enough for the tunnel — nothing depends on it
// for security — but it will not survive a probe that checks the chain, so a
// real one is better where the address is a domain.
func CertificateFor(cfg *config.Config) (tls.Certificate, error) {
	crt, key := strings.TrimSpace(cfg.TLSCert), strings.TrimSpace(cfg.TLSKey)
	if crt != "" || key != "" {
		if crt == "" || key == "" {
			return tls.Certificate{}, fmt.Errorf("tls_cert and tls_key must both be set")
		}
		if _, err := os.Stat(crt); err != nil {
			return tls.Certificate{}, fmt.Errorf("tls_cert: %w", err)
		}
		return tls.LoadX509KeyPair(crt, key)
	}
	host := strings.TrimSpace(cfg.TLSSNI)
	if host == "" {
		host = "localhost"
	}
	return selfSigned(host)
}

func selfSigned(host string) (tls.Certificate, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return tls.Certificate{}, err
	}
	tmpl := x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: host},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(2 * 365 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	if ip := net.ParseIP(host); ip != nil {
		tmpl.IPAddresses = []net.IP{ip}
	} else {
		tmpl.DNSNames = []string{host}
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &priv.PublicKey, priv)
	if err != nil {
		return tls.Certificate{}, err
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: priv}, nil
}

type dialer struct {
	addr   string
	sni    string
	verify bool
	inner  func(net.Conn) (net.Conn, error)
	log    *logx.Logger
}

func (d *dialer) Dial(ctx context.Context) (net.Conn, error) {
	var nd net.Dialer
	raw, err := nd.DialContext(ctx, "tcp", d.addr)
	if err != nil {
		return nil, err
	}
	// A real Chrome handshake, not Go's. The ClientHello is one of the few
	// parts of a TLS connection an observer can read in full, and Go's is
	// distinctive enough to single out on its own.
	cfg := &utls.Config{ServerName: d.sni, InsecureSkipVerify: !d.verify}
	tc := utls.UClient(raw, cfg, utls.HelloChrome_Auto)
	if err := tc.HandshakeContext(ctx); err != nil {
		_ = raw.Close()
		return nil, fmt.Errorf("wss: tls handshake: %w", err)
	}
	c, err := d.inner(tc)
	if err != nil {
		_ = tc.Close()
		return nil, err
	}
	return c, nil
}

func (d *dialer) Close() error { return nil }

type listener struct {
	ln    net.Listener
	inner func(net.Conn) (net.Conn, error)
	log   *logx.Logger

	once  sync.Once
	ready chan net.Conn
	fatal chan error
	done  chan struct{}
	dOnce sync.Once
}

// Accept completes TLS and the WebSocket upgrade off the accept path.
//
// Waiting for either here — even with a timeout — charges a stalled connection
// to every real peer behind it, which on a public port is what a scanner causes
// by accident. Each candidate is handled in its own goroutine and only finished
// connections come back.
func (l *listener) Accept() (net.Conn, error) {
	l.once.Do(l.start)
	select {
	case c := <-l.ready:
		return c, nil
	case err := <-l.fatal:
		return nil, err
	}
}

// maxPendingHandshakes bounds the goroutines a flood of connections can create.
const maxPendingHandshakes = 64

func (l *listener) start() {
	go func() {
		sem := make(chan struct{}, maxPendingHandshakes)
		for {
			raw, err := l.ln.Accept()
			if err != nil {
				select {
				case l.fatal <- err:
				default:
				}
				return
			}
			select {
			case sem <- struct{}{}:
			default:
				_ = raw.Close()
				continue
			}
			go func() {
				defer func() { <-sem }()
				_ = raw.SetDeadline(time.Now().Add(handshakeTimeout))
				c, err := l.inner(raw)
				if err != nil {
					_ = raw.Close()
					return
				}
				_ = raw.SetDeadline(time.Time{})
				select {
				case l.ready <- c:
				case <-l.done:
					_ = c.Close()
				}
			}()
		}
	}()
}

// handshakeTimeout bounds TLS plus the upgrade for one candidate.
const handshakeTimeout = 20 * time.Second

func (l *listener) Addr() net.Addr { return l.ln.Addr() }

func (l *listener) Close() error {
	l.dOnce.Do(func() { close(l.done) })
	return l.ln.Close()
}
