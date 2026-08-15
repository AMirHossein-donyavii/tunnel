// wan simulates the Iran<->Europe path for the carrier: constant one-way
// delay, uniform random loss, and an optional bandwidth ceiling. It sits
// between the two tunnel halves and relays UDP both ways, keeping one upstream
// socket per client source port the way a NAT does — the tunnel opens one
// carrier flow per queue, and folding them together makes every reply land on
// the wrong link.
//
// It exists because the container has no netem, and because a userspace relay
// is more controllable anyway: delay and loss are exactly what was asked for,
// with no qdisc semantics in the way.
package main

import (
	"flag"
	"log"
	"math/rand"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

var (
	delay = flag.Duration("delay", 70*time.Millisecond, "one-way delay")
	loss  = flag.Float64("loss", 0, "one-way loss probability (0..1)")
	mbit  = flag.Float64("mbit", 0, "one-way bandwidth ceiling in Mbit/s (0 = unlimited)")
	depth = flag.Int("depth", 400000, "delay-line depth in packets")
	_     = flag.Bool("perflow", false, "apply -mbit per carrier flow instead of in total")

	sent, lost, over atomic.Uint64
)

type item struct {
	b    []byte
	at   time.Time
	to   *net.UDPAddr // nil = write on a connected socket
	sock interface {
		Write([]byte) (int, error)
	}
	near *net.UDPConn
}

// line is a constant-delay FIFO: one goroutine, so order is preserved.
type line struct {
	ch chan item
}

func newLine() *line {
	l := &line{ch: make(chan item, *depth)}
	go func() {
		for it := range l.ch {
			if w := time.Until(it.at); w > 0 {
				time.Sleep(w)
			}
			if it.near != nil {
				_, _ = it.near.WriteToUDP(it.b, it.to)
			} else {
				_, _ = it.sock.Write(it.b)
			}
		}
	}()
	return l
}

type bucket struct {
	mu     sync.Mutex
	tokens float64
	last   time.Time
}

func (b *bucket) allow(n int) bool {
	if *mbit <= 0 {
		return true
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	now := time.Now()
	if b.last.IsZero() {
		b.last = now
	}
	b.tokens += now.Sub(b.last).Seconds() * *mbit * 125000
	b.last = now
	if max := *mbit * 125000 * 0.05; b.tokens > max {
		b.tokens = max
	}
	if b.tokens < float64(n) {
		return false
	}
	b.tokens -= float64(n)
	return true
}

func (l *line) admit(b *bucket, it item) {
	sent.Add(1)
	if *loss > 0 && rand.Float64() < *loss {
		lost.Add(1)
		return
	}
	if !b.allow(len(it.b)) {
		lost.Add(1)
		return
	}
	it.at = time.Now().Add(*delay)
	select {
	case l.ch <- it:
	default:
		over.Add(1)
	}
}

func main() {
	listen := flag.String("listen", "0.0.0.0:9000", "address the near side dials")
	upstream := flag.String("upstream", "", "address of the far side")
	flag.Parse()

	la, err := net.ResolveUDPAddr("udp", *listen)
	if err != nil {
		log.Fatal(err)
	}
	near, err := net.ListenUDP("udp", la)
	if err != nil {
		log.Fatal(err)
	}
	ua, err := net.ResolveUDPAddr("udp", *upstream)
	if err != nil {
		log.Fatal(err)
	}
	_ = near.SetReadBuffer(32 << 20)
	_ = near.SetWriteBuffer(32 << 20)

	up, down := newLine(), newLine()
	// Per-carrier-flow shaping. Transit that polices each connection separately
	// is the normal case on this route, and it is the one condition under which
	// spreading a single inner flow over several carrier links wins: with one
	// bucket per source port, one carrier link can never exceed the per-flow
	// ceiling no matter how much capacity the path has.
	perFlow := flag.Lookup("perflow").Value.String() == "true"
	shared := &bucket{}
	buckets := map[string]*bucket{}
	pick := func(key string) *bucket {
		if !perFlow {
			return shared
		}
		b, ok := buckets[key]
		if !ok {
			b = &bucket{}
			buckets[key] = b
		}
		return b
	}

	var mu sync.Mutex
	sessions := map[string]*net.UDPConn{}

	buf := make([]byte, 65536)
	for {
		n, from, err := near.ReadFromUDP(buf)
		if err != nil {
			return
		}
		key := from.String()
		mu.Lock()
		conn, ok := sessions[key]
		if !ok {
			conn, err = net.DialUDP("udp", nil, ua)
			if err != nil {
				mu.Unlock()
				continue
			}
			_ = conn.SetReadBuffer(32 << 20)
			_ = conn.SetWriteBuffer(32 << 20)
			sessions[key] = conn
			client := from
			db := pick(key)
			go func(c *net.UDPConn) {
				rb := make([]byte, 65536)
				for {
					m, err := c.Read(rb)
					if err != nil {
						return
					}
					down.admit(db, item{
						b: append([]byte(nil), rb[:m]...), near: near, to: client,
					})
				}
			}(conn)
		}
		b := pick(key)
		mu.Unlock()
		up.admit(b, item{b: append([]byte(nil), buf[:n]...), sock: conn})
	}
}

func init() {
	go func() {
		for range time.Tick(2 * time.Second) {
			log.Printf("relayed=%d lost=%d overflow=%d", sent.Load(), lost.Load(), over.Load())
		}
	}()
}
