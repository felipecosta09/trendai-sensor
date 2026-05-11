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
type AFPacket struct {
	spec    filterpkg.Spec
	sockets map[string]int // iface -> fd
	buf     int

	captured    atomic.Uint64
	kernelDrops atomic.Uint64 // cumulative; PACKET_STATISTICS resets on read so we accumulate here
	closed      sync.Once
}

// afpacketReadBuf sized to the classic pcap snaplen so jumbo frames (up to
// ~9 KB) survive without truncation. Each unix.Read reads exactly one frame;
// oversize buffer costs one stack allocation per reader goroutine, not per
// packet.
const afpacketReadBuf = 65535

func NewAFPacket(spec filterpkg.Spec) *AFPacket {
	return &AFPacket{spec: spec, sockets: make(map[string]int), buf: afpacketReadBuf}
}

func (a *AFPacket) Mode() string { return "afpacket" }

func (a *AFPacket) Start(ctx context.Context, ifaces []string) (<-chan Packet, error) {
	prog, err := filterpkg.Assemble(a.spec)
	if err != nil {
		return nil, fmt.Errorf("build cbpf: %w", err)
	}
	raw, err := bpf.Assemble(prog)
	if err != nil {
		return nil, fmt.Errorf("assemble cbpf: %w", err)
	}

	for _, name := range ifaces {
		fd, err := openSocket(name, raw)
		if err != nil {
			slog.Warn("afpacket open", "iface", name, "err", err)
			continue
		}
		a.sockets[name] = fd
	}
	if len(a.sockets) == 0 {
		return nil, errors.New("afpacket: no interfaces opened")
	}

	out := make(chan Packet, 1024)
	var wg sync.WaitGroup
	for name, fd := range a.sockets {
		wg.Add(1)
		go func(name string, fd int) {
			defer wg.Done()
			a.readLoop(ctx, name, fd, out)
		}(name, fd)
	}
	// unix.Read blocks indefinitely with no deadline; on a quiet node ctx
	// cancellation alone would never unblock it. Closing the fds here makes
	// the in-flight Read return EBADF, which the readLoop already handles.
	// Mirrors the TC-BPF ringbuf close-on-ctx pattern from v0.1.6.
	go func() {
		<-ctx.Done()
		_ = a.Close()
	}()
	go func() { wg.Wait(); close(out) }()
	return out, nil
}

func (a *AFPacket) readLoop(ctx context.Context, name string, fd int, out chan<- Packet) {
	buf := make([]byte, a.buf)
	for {
		if ctx.Err() != nil {
			return
		}
		n, err := unix.Read(fd, buf)
		if err != nil {
			if errors.Is(err, unix.EINTR) {
				continue
			}
			if errors.Is(err, unix.EBADF) {
				return
			}
			slog.Warn("afpacket read", "iface", name, "err", err)
			return
		}
		if n == 0 {
			continue
		}
		// Copy — buf is reused on next iteration. With a 1024-deep channel
		// the consumer generally reads before the next packet lands, but we
		// can't guarantee it.
		data := make([]byte, n)
		copy(data, buf[:n])
		a.captured.Add(1)
		select {
		case out <- Packet{Data: data, Iface: name, Direction: DirUnknown}:
		case <-ctx.Done():
			return
		}
	}
}

func (a *AFPacket) Stats() Stats {
	// PACKET_STATISTICS resets on read — fold per-socket deltas into our
	// cumulative counter so callers see monotonically-increasing values like
	// the TC-BPF backend.
	var delta uint64
	for _, fd := range a.sockets {
		d, err := readPacketStats(fd)
		if err == nil {
			delta += uint64(d)
		}
	}
	if delta > 0 {
		a.kernelDrops.Add(delta)
	}
	return Stats{
		CapturedPackets: a.captured.Load(),
		KernelDrops:     a.kernelDrops.Load(),
		FilterDrops:     map[string]uint64{},
	}
}

func (a *AFPacket) Close() error {
	a.closed.Do(func() {
		for _, fd := range a.sockets {
			_ = unix.Close(fd)
		}
	})
	return nil
}

func openSocket(name string, filter []bpf.RawInstruction) (int, error) {
	iface, err := net.InterfaceByName(name)
	if err != nil {
		return 0, err
	}
	// ETH_P_ALL = 0x0003 in host byte order; AF_PACKET expects network order.
	const ethPAll = 0x0003
	fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW|unix.SOCK_CLOEXEC, int(htons(ethPAll)))
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
