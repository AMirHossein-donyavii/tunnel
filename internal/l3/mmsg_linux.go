package l3

import (
	"net"
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"
)

// Batched receive for the raw-IP carriers.
//
// The carrier costs about 7.0 µs per packet end to end while the scheduler
// above it runs at the equivalent of 35 Gbit/s, so essentially all of the cost
// is the send and receive syscalls themselves — not framing, not the cipher,
// not queueing. That is what puts a per-core ceiling of roughly 1.6 Gbit/s on
// the ICMP carrier, and it is the only part of the data path where a
// significant amount of time is left to recover.
//
// recvmmsg collects many datagrams in one syscall. Measured on this machine at
// 1320-byte payloads:
//
//	one syscall per packet   3523 ns   374 MB/s
//	batch of 8               3355 ns   393 MB/s
//	batch of 32              2569 ns   514 MB/s
//	batch of 64              2367 ns   558 MB/s
//
// Only the receive side is batched, and the send side deliberately is not.
//
// Batching sends was built and then removed, because it was measured and it was
// slower. sendmmsg was wired into the carrier with a flush at the one point the
// pump knows it has nothing left to send — so no packet ever waited for another
// packet — and the result was worse both ways: the carrier benchmark went from
// 6075 to 6836-7563 ns per packet, and four concurrent streams through a real
// tunnel went from 949 to 901 and 739 Mbit/s.
//
// The reason is the shape of this data plane rather than anything wrong with
// sendmmsg. With link striping there are several writers draining one transmit
// queue, so each of them pops a packet, sends it, finds the queue empty and
// flushes: the batch is nearly always a single frame, and all that is left is
// the cost of packing it into an arena and building a header for it. A batch of
// one is a syscall with paperwork.
//
// So the receive side is the half worth batching, and it is the half a caller
// cannot batch for itself: a reader loop has no way to know a second packet is
// waiting until it asks.
//
// Nothing about the wire format or the protocol changes. This is the same
// packets through the same socket, collected in fewer trips into the kernel.

const (
	// mmsgBatch is how many datagrams one recvmmsg may collect. 64 is where the
	// measured gain flattens; past it the per-call setup grows faster than the
	// syscall saved.
	mmsgBatch = 64
	// mmsgBufSize must hold the largest carrier datagram including its IP
	// header, which a raw socket delivers for IPv4.
	mmsgBufSize = 2048
)

// mmsghdr mirrors the kernel's struct mmsghdr: a msghdr plus the length the
// kernel fills in for that message. x/sys does not export it and the layout is
// stable ABI.
type mmsghdr struct {
	hdr unix.Msghdr
	n   uint32
	_   [4]byte
}

// mmsgReader hands out received datagrams one at a time, refilling from the
// socket in batches. It replaces a PacketConn.ReadFrom loop without changing
// what that loop sees, so read deadlines, closure and transient errors all
// behave exactly as before.
//
// The returned payload is only valid until the next call: every caller here
// copies it into a pooled buffer before going round again, which is what makes
// borrowing it safe and is the reason there is no copy in this path at all.
type mmsgReader struct {
	pc net.PacketConn
	rc syscall.RawConn
	// stripIP4 removes the IPv4 header the kernel prepends on a raw socket.
	//
	// This is not optional and it is easy to miss: Go's own ReadFrom for an
	// "ip4:" network strips that header before returning, so code written
	// against it never sees one. Going to the socket directly gets the header
	// back, and every frame then fails to parse — which is exactly what the
	// carrier tests caught. IPv6 raw sockets do not prepend a header, so this is
	// false there.
	stripIP4 bool

	bufs  [][]byte
	iovs  []unix.Iovec
	names [][unix.SizeofSockaddrAny]byte
	hdrs  []mmsghdr

	n, i int // messages in the current batch, and the next one to hand out

	// The address of the last datagram, reused while it does not change. A
	// tunnel receives nearly every packet from the same peer, so this removes
	// the per-packet address allocation in the common case. It is only ever
	// read after being published, never mutated.
	lastIP   net.IP
	lastAddr *net.IPAddr

	// fallback is used when the socket cannot be driven directly, in which case
	// this degrades to exactly the previous behaviour.
	fallback []byte
}

// newMmsgReader prepares a batched reader for pc. It never fails: a socket that
// will not yield its descriptor falls back to one ReadFrom per packet.
func newMmsgReader(pc net.PacketConn, stripIP4 bool) *mmsgReader {
	r := &mmsgReader{pc: pc, stripIP4: stripIP4}
	sc, ok := pc.(syscall.Conn)
	if !ok {
		r.fallback = make([]byte, 64*1024)
		return r
	}
	rc, err := sc.SyscallConn()
	if err != nil {
		r.fallback = make([]byte, 64*1024)
		return r
	}
	r.rc = rc
	r.bufs = make([][]byte, mmsgBatch)
	r.iovs = make([]unix.Iovec, mmsgBatch)
	r.names = make([][unix.SizeofSockaddrAny]byte, mmsgBatch)
	r.hdrs = make([]mmsghdr, mmsgBatch)
	for i := range r.bufs {
		r.bufs[i] = make([]byte, mmsgBufSize)
		r.iovs[i].Base = &r.bufs[i][0]
		r.iovs[i].SetLen(mmsgBufSize)
		r.hdrs[i].hdr.Name = &r.names[i][0]
		r.hdrs[i].hdr.Namelen = uint32(unix.SizeofSockaddrAny)
		r.hdrs[i].hdr.Iov = &r.iovs[i]
		r.hdrs[i].hdr.SetIovlen(1)
	}
	return r
}

// next returns the next datagram and the address it came from. The payload is
// valid until the following call.
func (r *mmsgReader) next() ([]byte, net.Addr, error) {
	if r.fallback != nil {
		// The fallback goes through ReadFrom, which has already stripped the
		// header — so it is returned as-is whatever stripIP4 says.
		n, src, err := r.pc.ReadFrom(r.fallback)
		if err != nil {
			return nil, nil, err
		}
		return r.fallback[:n], src, nil
	}
	for {
		for r.i >= r.n {
			if err := r.fill(); err != nil {
				return nil, nil, err
			}
		}
		i := r.i
		r.i++
		n := int(r.hdrs[i].n)
		if n > mmsgBufSize {
			n = mmsgBufSize
		}
		b := r.bufs[i][:n]
		if r.stripIP4 {
			// A datagram that is not a well-formed IPv4 packet is one bad
			// datagram, and it is skipped rather than returned as an error.
			// Anyone can send a raw socket anything; reporting it as a read
			// failure would let a stranger's malformed packet end the read loop
			// and take every link on this socket down with it.
			if len(b) < 20 || b[0]>>4 != 4 {
				badDatagrams.Add(1)
				continue
			}
			hlen := int(b[0]&0x0f) * 4
			if hlen < 20 || hlen > len(b) {
				badDatagrams.Add(1)
				continue
			}
			b = b[hlen:]
		}
		return b, r.addr(i), nil
	}
}

// fill blocks until at least one datagram is available, then collects up to a
// full batch of them in one syscall.
func (r *mmsgReader) fill() error {
	var got int
	var serr syscall.Errno
	err := r.rc.Read(func(fd uintptr) bool {
		for i := range r.hdrs {
			r.hdrs[i].hdr.Namelen = uint32(unix.SizeofSockaddrAny)
			r.hdrs[i].n = 0
		}
		n, _, e := unix.Syscall6(unix.SYS_RECVMMSG, fd,
			uintptr(unsafe.Pointer(&r.hdrs[0])), uintptr(len(r.hdrs)),
			unix.MSG_DONTWAIT, 0, 0)
		if e == unix.EAGAIN || e == unix.EWOULDBLOCK || e == unix.EINTR {
			return false // nothing there yet; let the poller wait for readiness
		}
		got, serr = int(n), e
		return true
	})
	if err != nil {
		return err // deadline, or the socket was closed
	}
	if serr != 0 {
		return serr
	}
	if got <= 0 {
		return unix.EAGAIN
	}
	r.n, r.i = got, 0
	return nil
}

// addr decodes the source of message i, reusing the previous address object
// while the peer does not change.
func (r *mmsgReader) addr(i int) net.Addr {
	raw := r.names[i][:]
	var ip net.IP
	switch uint16(raw[0]) | uint16(raw[1])<<8 {
	case unix.AF_INET:
		ip = net.IP(raw[4:8])
	case unix.AF_INET6:
		ip = net.IP(raw[8:24])
	default:
		return r.lastAddr // unknown family: nothing useful to say about it
	}
	if r.lastIP.Equal(ip) {
		return r.lastAddr
	}
	// A fresh copy: callers keep the address (the listener writes replies back
	// to it), so it must not alias a buffer the next batch overwrites.
	cp := make(net.IP, len(ip))
	copy(cp, ip)
	r.lastIP = cp
	r.lastAddr = &net.IPAddr{IP: cp}
	return r.lastAddr
}
