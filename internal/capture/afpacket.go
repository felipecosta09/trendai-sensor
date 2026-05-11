//go:build linux

package capture

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"sync"
	"sync/atomic"
	"unsafe"

	"golang.org/x/net/bpf"
	"golang.org/x/sys/unix"

	filterpkg "github.com/trendai/sensor/internal/filter"
)

// bpf.RawInstruction and unix.SockFilter are layout-compatible: both are
// {uint16, uint8, uint8, uint32}. We assert this at package init via an
// unsafe.Sizeof check so a future x/sys/unix bump that breaks the layout
// fails loudly instead of silently corrupting the filter.
var _ = [1]struct{}{}[unsafe.Sizeof(bpf.RawInstruction{})-unsafe.Sizeof(unix.SockFilter{})]

// AFPacket is a CGO-free AF_PACKET SOCK_RAW capturer. Each interface gets one
// socket with a classic BPF filter attached via SO_ATTACH_FILTER so the
// kernel drops DNS/VXLAN/metadata/non-IPv4 traffic before userspace reads
// anything. Used as a fallback when TC-BPF isn't available.
//
// Sockets are non-blocking and multiplexed through a single epoll fd
// alongside an eventfd used as a shutdown signal. close(2) on a blocking fd
// does not reliably wake a concurrently-blocked read() on Linux (see the
// "Multithreaded processes and close()" note in close(2)); epoll_wait is
// interruptible by the eventfd becoming readable, which is how Close makes
// shutdown deterministic.
type AFPacket struct {
	spec      filterpkg.Spec
	socketsMu sync.RWMutex
	sockets   map[string]int    // iface -> fd (non-blocking)
	ifaceByFD map[int32]string  // fd -> iface (for eventLoop)
	rawOnce   sync.Once
	raw       []bpf.RawInstruction
	rawErr    error
	epollFD   int
	eventFD   int
	buf       int

	captured    atomic.Uint64
	kernelDrops atomic.Uint64 // cumulative; PACKET_STATISTICS resets on read so we accumulate here
	closed      sync.Once
	loopWG      sync.WaitGroup // incremented before eventLoop spawns, zeroed when it returns
}

// afpacketReadBuf sized to the classic pcap snaplen so jumbo frames (up to
// ~9 KB) survive without truncation. One buffer per event loop, reused.
const afpacketReadBuf = 65535

func NewAFPacket(spec filterpkg.Spec) *AFPacket {
	return &AFPacket{
		spec:      spec,
		sockets:   make(map[string]int),
		ifaceByFD: make(map[int32]string),
		epollFD:   -1,
		eventFD:   -1,
		buf:       afpacketReadBuf,
	}
}

func (a *AFPacket) Mode() string { return "afpacket" }

func (a *AFPacket) Start(ctx context.Context, ifaces []string) (<-chan Packet, error) {
	// Cache the assembled cBPF so Attach can reuse it without re-assembling.
	a.rawOnce.Do(func() {
		prog, err := filterpkg.Assemble(a.spec)
		if err != nil {
			a.rawErr = fmt.Errorf("build cbpf: %w", err)
			return
		}
		raw, err := bpf.Assemble(prog)
		if err != nil {
			a.rawErr = fmt.Errorf("assemble cbpf: %w", err)
			return
		}
		a.raw = raw
	})
	if a.rawErr != nil {
		return nil, a.rawErr
	}

	for _, name := range ifaces {
		fd, err := openSocket(name, a.raw)
		if err != nil {
			slog.Warn("afpacket open", "iface", name, "err", err)
			continue
		}
		a.sockets[name] = fd
		a.ifaceByFD[int32(fd)] = name
	}
	if len(a.sockets) == 0 {
		slog.Warn("afpacket: no interfaces opened, waiting for dynamic attach")
	}

	efd, err := unix.Eventfd(0, unix.EFD_CLOEXEC|unix.EFD_NONBLOCK)
	if err != nil {
		a.closeFDs()
		return nil, fmt.Errorf("eventfd: %w", err)
	}
	a.eventFD = efd

	epfd, err := unix.EpollCreate1(unix.EPOLL_CLOEXEC)
	if err != nil {
		a.closeFDs()
		return nil, fmt.Errorf("epoll_create1: %w", err)
	}
	a.epollFD = epfd

	// Register eventfd first so shutdown wins any race with a pending
	// packet — epoll_wait returns events in fd-ready order and we check
	// the eventfd before draining sockets.
	if err := unix.EpollCtl(epfd, unix.EPOLL_CTL_ADD, efd,
		&unix.EpollEvent{Events: unix.EPOLLIN, Fd: int32(efd)}); err != nil {
		a.closeFDs()
		return nil, fmt.Errorf("epoll_ctl eventfd: %w", err)
	}
	for name, fd := range a.sockets {
		if err := unix.EpollCtl(epfd, unix.EPOLL_CTL_ADD, fd,
			&unix.EpollEvent{Events: unix.EPOLLIN, Fd: int32(fd)}); err != nil {
			a.closeFDs()
			return nil, fmt.Errorf("epoll_ctl %s: %w", name, err)
		}
	}

	out := make(chan Packet, 1024)

	// Translate ctx cancel into Close. Close writes to the eventfd which
	// wakes epoll_wait; the event loop drops its reference and returns,
	// closing `out`, which lets main's `for range packets` exit.
	go func() {
		<-ctx.Done()
		_ = a.Close()
	}()

	a.loopWG.Add(1)
	go func() {
		defer a.loopWG.Done()
		defer close(out)
		a.eventLoop(ctx, out)
	}()

	return out, nil
}

// eventLoop blocks in epoll_wait until a socket fd is ready or the eventfd
// is poked by Close. Single goroutine — epoll multiplexes readiness across
// all interfaces, no per-iface reader goroutine needed.
//
// a.epollFD / a.eventFD are set exactly once in Start before this goroutine
// is spawned and are never written again. closeFDs closes the fds but does
// not mutate the fields, so concurrent reads here are race-free without
// additional synchronization. Closing an fd the goroutine still references
// is safe — the kernel's fd→file mapping is independent of the integer
// value we hold, and a stale integer at worst yields EBADF which we handle.
func (a *AFPacket) eventLoop(ctx context.Context, out chan<- Packet) {
	events := make([]unix.EpollEvent, 256)
	buf := make([]byte, a.buf)
	for {
		n, err := unix.EpollWait(a.epollFD, events, -1)
		if err != nil {
			if errors.Is(err, unix.EINTR) {
				continue
			}
			// EBADF means Close raced ahead of us and closed the epoll fd
			// before we returned — treated as a clean shutdown signal.
			if errors.Is(err, unix.EBADF) {
				return
			}
			slog.Warn("afpacket epoll_wait", "err", err)
			return
		}
		for i := 0; i < n; i++ {
			ev := events[i]
			if ev.Fd == int32(a.eventFD) {
				return
			}
			a.socketsMu.RLock()
			name := a.ifaceByFD[ev.Fd]
			a.socketsMu.RUnlock()
			if !a.drainSocket(ctx, int(ev.Fd), name, buf, out) {
				return
			}
		}
	}
}

// drainSocket reads every ready packet on fd until EAGAIN. Returns false
// when the event loop should exit (ctx cancelled mid-send or fd closed).
func (a *AFPacket) drainSocket(ctx context.Context, fd int, name string, buf []byte, out chan<- Packet) bool {
	for {
		nr, err := unix.Read(fd, buf)
		if err != nil {
			if errors.Is(err, unix.EAGAIN) || errors.Is(err, unix.EWOULDBLOCK) {
				return true
			}
			if errors.Is(err, unix.EINTR) {
				continue
			}
			if errors.Is(err, unix.EBADF) {
				return false
			}
			slog.Warn("afpacket read", "iface", name, "err", err)
			return false
		}
		if nr == 0 {
			return true
		}
		// Copy — buf is reused on the next read. With a 1024-deep channel
		// the consumer generally reads before the next packet lands, but
		// we can't guarantee it.
		data := make([]byte, nr)
		copy(data, buf[:nr])
		a.captured.Add(1)
		select {
		case out <- Packet{Data: data, Iface: name, Direction: DirUnknown}:
		case <-ctx.Done():
			return false
		}
	}
}

// wakeShutdown breaks epoll_wait by posting to the eventfd. The counter
// saturates at uint64 max so repeated calls are safe; writes are
// non-blocking via EFD_NONBLOCK.
func (a *AFPacket) wakeShutdown() {
	if a.eventFD < 0 {
		return
	}
	var one [8]byte
	binary.LittleEndian.PutUint64(one[:], 1)
	_, _ = unix.Write(a.eventFD, one[:])
}

func (a *AFPacket) Stats() Stats {
	// PACKET_STATISTICS resets on read — fold per-socket deltas into our
	// cumulative counter so callers see monotonically-increasing values like
	// the TC-BPF backend.
	var delta uint64
	a.socketsMu.RLock()
	for _, fd := range a.sockets {
		d, err := readPacketStats(fd)
		if err == nil {
			delta += uint64(d)
		}
	}
	a.socketsMu.RUnlock()
	if delta > 0 {
		a.kernelDrops.Add(delta)
	}
	return Stats{
		CapturedPackets: a.captured.Load(),
		KernelDrops:     a.kernelDrops.Load(),
		FilterDrops:     map[string]uint64{},
	}
}

func (a *AFPacket) Attach(iface string) error {
	a.socketsMu.RLock()
	_, already := a.sockets[iface]
	a.socketsMu.RUnlock()
	if already {
		return nil
	}
	// Assemble cBPF if Start was called with an empty interface list.
	a.rawOnce.Do(func() {
		prog, err := filterpkg.Assemble(a.spec)
		if err != nil {
			a.rawErr = fmt.Errorf("build cbpf: %w", err)
			return
		}
		raw, err := bpf.Assemble(prog)
		if err != nil {
			a.rawErr = fmt.Errorf("assemble cbpf: %w", err)
			return
		}
		a.raw = raw
	})
	if a.rawErr != nil {
		return a.rawErr
	}
	fd, err := openSocket(iface, a.raw)
	if err != nil {
		return fmt.Errorf("afpacket attach %s: %w", iface, err)
	}
	if err := unix.EpollCtl(a.epollFD, unix.EPOLL_CTL_ADD, fd,
		&unix.EpollEvent{Events: unix.EPOLLIN, Fd: int32(fd)}); err != nil {
		_ = unix.Close(fd)
		return fmt.Errorf("epoll_ctl attach %s: %w", iface, err)
	}
	a.socketsMu.Lock()
	a.sockets[iface] = fd
	a.ifaceByFD[int32(fd)] = iface
	a.socketsMu.Unlock()
	return nil
}

func (a *AFPacket) Detach(iface string) error {
	a.socketsMu.Lock()
	fd, ok := a.sockets[iface]
	if !ok {
		a.socketsMu.Unlock()
		return nil
	}
	delete(a.sockets, iface)
	delete(a.ifaceByFD, int32(fd))
	a.socketsMu.Unlock()
	_ = unix.EpollCtl(a.epollFD, unix.EPOLL_CTL_DEL, fd, nil)
	_ = unix.Close(fd)
	return nil
}

// Close is idempotent (sync.Once) and blocks until the event loop has
// observed the shutdown signal and returned. Waiting is required because
// close(2) on a Linux epoll fd or eventfd does NOT reliably wake a blocked
// epoll_wait in another thread — if we closed the eventfd between
// wakeShutdown and the kernel delivering the readable state, the signal
// would be lost and epoll_wait would block forever. loopWG.Wait() makes
// the sequence (wakeShutdown → eventLoop exits → closeFDs) explicit.
//
// loopWG has a zero counter when Start was never called (e.g. tests
// exercising closeFDs on a partially-constructed AFPacket), so Wait
// returns immediately in that case.
func (a *AFPacket) Close() error {
	a.closed.Do(func() {
		a.wakeShutdown()
		a.loopWG.Wait()
		a.closeFDs()
	})
	return nil
}

// closeFDs releases all owned fds. Safe to invoke on a partially-constructed
// AFPacket (fields default to -1); Close is the public entry, this is the
// internal cleanup shared with Start's error paths.
//
// Deliberately does NOT write -1 back into the struct fields after closing:
// eventLoop reads a.epollFD / a.eventFD without synchronization, relying on
// the invariant that those fields are set exactly once in Start before the
// goroutine is spawned and never written afterwards. sync.Once on Close
// guarantees closeFDs runs at most once post-Start, so there is no
// double-close hazard that the -1 sentinel would guard against.
func (a *AFPacket) closeFDs() {
	a.socketsMu.Lock()
	for _, fd := range a.sockets {
		_ = unix.Close(fd)
	}
	// Clear maps so a post-close Detach finds nothing and cannot operate on
	// stale (or OS-reused) fd integers.
	a.sockets = make(map[string]int)
	a.ifaceByFD = make(map[int32]string)
	a.socketsMu.Unlock()
	if a.epollFD >= 0 {
		_ = unix.Close(a.epollFD)
	}
	if a.eventFD >= 0 {
		_ = unix.Close(a.eventFD)
	}
}

func openSocket(name string, filter []bpf.RawInstruction) (int, error) {
	iface, err := net.InterfaceByName(name)
	if err != nil {
		return 0, err
	}
	// ETH_P_ALL = 0x0003 in host byte order; AF_PACKET expects network order.
	// SOCK_NONBLOCK is required for the epoll event loop — blocking reads
	// would defeat the whole point of multiplexing.
	const ethPAll = 0x0003
	fd, err := unix.Socket(unix.AF_PACKET,
		unix.SOCK_RAW|unix.SOCK_CLOEXEC|unix.SOCK_NONBLOCK,
		int(htons(ethPAll)))
	if err != nil {
		return 0, fmt.Errorf("socket: %w", err)
	}
	sll := &unix.SockaddrLinklayer{Protocol: htons(ethPAll), Ifindex: iface.Index}
	if err := unix.Bind(fd, sll); err != nil {
		_ = unix.Close(fd)
		return 0, fmt.Errorf("bind: %w", err)
	}
	if err := attachFilter(fd, filter); err != nil {
		_ = unix.Close(fd)
		return 0, fmt.Errorf("attach filter: %w", err)
	}
	return fd, nil
}

// attachFilter installs a classic BPF program via SO_ATTACH_FILTER.
//
// Uses unix.SockFprog so the struct layout (and pointer alignment padding)
// matches the kernel's struct sock_fprog on every supported GOARCH — amd64,
// arm64, 386, etc. — without hand-rolled padding bytes. The pointer cast is
// safe because bpf.RawInstruction and unix.SockFilter have identical field
// layouts (see the unsafe.Sizeof assertion at the top of this file).
func attachFilter(fd int, prog []bpf.RawInstruction) error {
	if len(prog) == 0 {
		return errors.New("empty filter")
	}
	fp := unix.SockFprog{
		Len:    uint16(len(prog)),
		Filter: (*unix.SockFilter)(unsafe.Pointer(&prog[0])),
	}
	return unix.SetsockoptSockFprog(fd, unix.SOL_SOCKET, unix.SO_ATTACH_FILTER, &fp)
}

// readPacketStats returns packets/drops from PACKET_STATISTICS (resets on read).
func readPacketStats(fd int) (uint32, error) {
	type tpacketStats struct {
		Packets uint32
		Drops   uint32
	}
	var s tpacketStats
	size := uint32(unsafe.Sizeof(s))
	_, _, e := unix.Syscall6(unix.SYS_GETSOCKOPT,
		uintptr(fd), unix.SOL_PACKET, unix.PACKET_STATISTICS,
		uintptr(unsafe.Pointer(&s)), uintptr(unsafe.Pointer(&size)), 0)
	if e != 0 {
		return 0, e
	}
	return s.Drops, nil
}

func htons(v uint16) uint16 {
	var b [2]byte
	binary.BigEndian.PutUint16(b[:], v)
	return *(*uint16)(unsafe.Pointer(&b[0]))
}
