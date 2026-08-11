// Package quic carries the tunnel inside QUIC — the transport underneath HTTP/3.
//
// Every other stream transport here rides on TCP, and on a path that loses
// packets TCP is the wrong shape twice over. A single loss stalls everything
// behind it until the retransmission arrives, because the kernel will not
// deliver bytes out of order; and the loss is read as congestion, so the sender
// slows down even when the loss was a flaky link rather than a full queue. On a
// long, lossy international route that is exactly the behaviour that turns a
// fast link into a slow tunnel.
//
// QUIC carries many independent streams over one UDP flow: a loss holds up only
// the stream it belonged to, the others keep moving, and recovery is driven by
// a modern loss detector rather than by a duplicate-ACK rule from the 1980s.
// Because the whole connection lives in userspace, its congestion control and
// flow-control windows are ours to size — the receive window here follows the
// path rather than a number picked from how much RAM the server has.
//
// It is also good camouflage: the connection is TLS 1.3 on UDP with the ALPN
// that HTTP/3 uses, so to anything watching it looks like a browser talking to
// a modern website — traffic that is now too common to block wholesale.
//
// As with wss, the TLS is camouflage and not the security boundary: the
// tunnel's own handshake still authenticates and encrypts everything inside.
package quic

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	quicgo "github.com/quic-go/quic-go"

	"github.com/emergency-tunnel/et/internal/config"
	"github.com/emergency-tunnel/et/internal/logx"
	"github.com/emergency-tunnel/et/internal/nettune"
	"github.com/emergency-tunnel/et/internal/transport"
	"github.com/emergency-tunnel/et/internal/transport/wss"
)

func init() { transport.Register(&quicTransport{}) }

// alpn is the HTTP/3 identifier. The tunnel speaks nothing like HTTP/3, but the
// ALPN travels in the clear in the TLS handshake and is one of the few things a
// filter can match on cheaply. Announcing the protocol that the overwhelming
// majority of QUIC on the internet is makes this connection unremarkable.
const alpn = "h3"

// handshakeTO bounds the QUIC handshake. It is generous because this transport
// is chosen for paths that are already slow.
const handshakeTO = 15 * time.Second

type quicTransport struct{}

func (*quicTransport) Name() string       { return "quic" }
func (*quicTransport) Experimental() bool { return false }
func (*quicTransport) Summary() string {
	return "QUIC/HTTP3 over UDP — one loss does not stall the rest; looks like a browser"
}

// tuning builds the QUIC config.
//
// The receive windows are the throughput ceiling in the same way the mux window
// is: a stream can have at most one window in flight, so it can carry at most
// window/RTT. quic-go's defaults (512 KiB stream, 1.5 MiB connection) come to
// about 40 Mbit/s per stream over a 100 ms route, which is well under what these
// paths carry. Both are given a large ceiling and left to quic-go's autotuner,
// which grows toward it as it measures the path — the same principle as the
// mux window: follow the path, do not guess it from the server's RAM.
func tuning(cfg *config.Config) *quicgo.Config {
	const (
		initialStream = 1 << 20  // 1 MiB
		maxStream     = 16 << 20 // ceiling for one stream
		initialConn   = 2 << 20
		maxConn       = 64 << 20 // ceiling across all streams on the connection
	)
	q := &quicgo.Config{
		InitialStreamReceiveWindow:     initialStream,
		MaxStreamReceiveWindow:         maxStream,
		InitialConnectionReceiveWindow: initialConn,
		MaxConnectionReceiveWindow:     maxConn,
		MaxIdleTimeout:                 30 * time.Second,
		// Without this a NAT on the path drops the mapping during a quiet
		// moment and the next packet goes nowhere. Cheap, and the difference
		// between a tunnel that survives an idle minute and one that does not.
		KeepAlivePeriod:    10 * time.Second,
		MaxIncomingStreams: 256,
	}
	if cfg.Profile == "resource" {
		// A tiny VPS cannot hold 64 MiB of reassembly buffers; keep the ceiling
		// within reach of the box while still leaving room to grow.
		q.MaxStreamReceiveWindow = 4 << 20
		q.MaxConnectionReceiveWindow = 16 << 20
	}
	return q
}

// listenUDP opens the QUIC socket with a receive buffer sized for bursts.
//
// quic-go recovers from loss well, but a datagram the kernel dropped because
// the socket queue was full never reaches it to be recovered — that is loss the
// tunnel causes itself. The send side stays modest for the usual reason: bytes
// queued in the socket are past the point where anything can reorder them.
func listenUDP(port int, cfg *config.Config) (*net.UDPConn, error) {
	pc, err := net.ListenUDP("udp", &net.UDPAddr{Port: port})
	if err != nil {
		return nil, fmt.Errorf("quic listen :%d: %w", port, err)
	}
	snd, rcv := nettune.BufSizes(cfg.Profile, cfg.SoSndbuf, cfg.SoRcvbuf)
	if rcv > 0 {
		_ = pc.SetReadBuffer(rcv)
	}
	if snd > 0 {
		_ = pc.SetWriteBuffer(snd)
	}
	return pc, nil
}

func (*quicTransport) NewDialer(cfg *config.Config, log *logx.Logger) (transport.Dialer, error) {
	if strings.TrimSpace(cfg.Peer) == "" {
		return nil, fmt.Errorf("transport %q: peer is required on the dialing side", "quic")
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
		qcfg:   tuning(cfg),
		cfg:    cfg,
		log:    log,
	}, nil
}

func (*quicTransport) NewListener(cfg *config.Config, log *logx.Logger) (transport.Listener, error) {
	cert, err := wss.CertificateFor(cfg)
	if err != nil {
		return nil, err
	}
	pc, err := listenUDP(cfg.TunnelPort, cfg)
	if err != nil {
		return nil, err
	}
	ln, err := quicgo.Listen(pc, &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS13,
		NextProtos:   []string{alpn},
	}, tuning(cfg))
	if err != nil {
		_ = pc.Close()
		return nil, fmt.Errorf("quic listen: %w", err)
	}
	log.Info("quic transport listening on :%d (udp)", cfg.TunnelPort)
	l := &listener{
		ln:    ln,
		pc:    pc,
		log:   log,
		ready: make(chan net.Conn, 16),
		fatal: make(chan error, 1),
		done:  make(chan struct{}),
	}
	return l, nil
}

// ---- dialer -----------------------------------------------------------------

// dialer holds ONE QUIC connection and opens a stream per Dial.
//
// The engine asks for several links and runs a mux session over each. Giving
// each its own QUIC connection would mean several handshakes, several
// congestion controllers competing with each other over one path, and several
// UDP flows for an observer to correlate. One connection with a stream each is
// what QUIC is for: the streams are independent — a loss stalls only its own —
// while sharing a single congestion controller that sees the whole path, and a
// single 4-tuple that looks like one browser session.
type dialer struct {
	addr   string
	sni    string
	verify bool
	qcfg   *quicgo.Config
	cfg    *config.Config
	log    *logx.Logger

	mu   sync.Mutex
	conn quicgo.Connection
}

// connection returns the shared QUIC connection, dialing a new one if there is
// none or the current one has died.
func (d *dialer) connection(ctx context.Context) (quicgo.Connection, error) {
	d.mu.Lock()
	defer d.mu.Unlock()

	if d.conn != nil {
		select {
		case <-d.conn.Context().Done(): // closed by peer, idle timeout, or error
			d.conn = nil
		default:
			return d.conn, nil
		}
	}

	pc, err := listenUDP(0, d.cfg) // ephemeral local port, buffers sized as above
	if err != nil {
		return nil, err
	}
	raddr, err := net.ResolveUDPAddr("udp", d.addr)
	if err != nil {
		_ = pc.Close()
		return nil, err
	}
	hctx, cancel := context.WithTimeout(ctx, handshakeTO)
	defer cancel()
	conn, err := quicgo.Dial(hctx, pc, raddr, &tls.Config{
		ServerName:         d.sni,
		InsecureSkipVerify: !d.verify,
		MinVersion:         tls.VersionTLS13,
		NextProtos:         []string{alpn},
	}, d.qcfg)
	if err != nil {
		_ = pc.Close()
		return nil, fmt.Errorf("quic: handshake with %s: %w", d.addr, err)
	}
	d.conn = conn
	return conn, nil
}

func (d *dialer) Dial(ctx context.Context) (net.Conn, error) {
	conn, err := d.connection(ctx)
	if err != nil {
		return nil, err
	}
	st, err := conn.OpenStreamSync(ctx)
	if err != nil {
		// The connection died between being handed out and being used. Drop it
		// so the next attempt dials a fresh one instead of retrying a corpse.
		d.mu.Lock()
		if d.conn == conn {
			d.conn = nil
		}
		d.mu.Unlock()
		return nil, fmt.Errorf("quic: open stream: %w", err)
	}
	// A stream is not created on the peer until it carries a byte, so the
	// listener would not see this link until the tunnel's own handshake spoke
	// first. That is fine — the client speaks first — but the stream must be
	// opened synchronously (above) so ordering is well defined.
	return &streamConn{Stream: st, local: conn.LocalAddr(), remote: conn.RemoteAddr()}, nil
}

func (d *dialer) Close() error {
	d.mu.Lock()
	conn := d.conn
	d.conn = nil
	d.mu.Unlock()
	if conn != nil {
		return conn.CloseWithError(0, "")
	}
	return nil
}

// ---- listener ---------------------------------------------------------------

type listener struct {
	ln  *quicgo.Listener
	pc  *net.UDPConn
	log *logx.Logger

	once  sync.Once
	ready chan net.Conn
	fatal chan error
	done  chan struct{}
	dOnce sync.Once
}

// Accept returns finished links only.
//
// Accepting a QUIC connection and then waiting on its first stream inline would
// charge a peer that connects and says nothing to every real peer behind it —
// the accept-path stall this project has already been bitten by on the L3
// listeners. Connections are taken in one goroutine and their streams in
// another per connection, so a silent peer costs nothing but its own goroutine.
func (l *listener) Accept() (net.Conn, error) {
	l.once.Do(l.start)
	select {
	case c := <-l.ready:
		return c, nil
	case err := <-l.fatal:
		return nil, err
	}
}

func (l *listener) start() {
	go func() {
		for {
			conn, err := l.ln.Accept(context.Background())
			if err != nil {
				select {
				case l.fatal <- err:
				case <-l.done:
				}
				return
			}
			go l.serve(conn)
		}
	}()
}

// serve hands every stream on one QUIC connection to Accept as its own link.
func (l *listener) serve(conn quicgo.Connection) {
	for {
		st, err := conn.AcceptStream(context.Background())
		if err != nil {
			// One connection ending is not the listener ending: log at debug and
			// let the others carry on.
			l.log.Debug("quic: connection from %s ended: %v", conn.RemoteAddr(), err)
			return
		}
		c := &streamConn{Stream: st, local: conn.LocalAddr(), remote: conn.RemoteAddr()}
		select {
		case l.ready <- c:
		case <-l.done:
			_ = c.Close()
			return
		}
	}
}

func (l *listener) Addr() net.Addr { return l.ln.Addr() }

func (l *listener) Close() error {
	l.dOnce.Do(func() { close(l.done) })
	err := l.ln.Close()
	_ = l.pc.Close()
	return err
}

// ---- stream as net.Conn ------------------------------------------------------

// streamConn presents one QUIC stream as a net.Conn.
//
// quic.Stream already has Read, Write, Close and the deadlines; it lacks only
// the addresses, which belong to the connection the stream rides on.
type streamConn struct {
	quicgo.Stream
	local  net.Addr
	remote net.Addr
}

func (c *streamConn) LocalAddr() net.Addr  { return c.local }
func (c *streamConn) RemoteAddr() net.Addr { return c.remote }

// Close shuts down both directions.
//
// quic.Stream.Close only closes the sending side — the stream stays open for
// reading, and a caller that treats it as a net.Conn (which is every caller
// here) would leak a half-open stream per link for the life of the process.
func (c *streamConn) Close() error {
	c.CancelRead(0)
	return c.Stream.Close()
}
