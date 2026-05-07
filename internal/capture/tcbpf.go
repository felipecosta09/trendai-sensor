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

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
	"github.com/vishvananda/netlink"

	"github.com/trendai/sensor/internal/filter"
)

// Index of DROP_RB_FULL in the BPF drop_counters map. Filter reasons occupy
// indices 0..len(filter.AllReasons)-1; rb_full sits one past the end.
const dropRBFullIndex = uint32(7)

// Generate Go bindings for bpf/filter.c. Requires clang + llvm (for
// llvm-strip) + libbpf-dev + linux-libc-dev (Debian: apt install clang llvm
// libbpf-dev linux-libc-dev).
// The -target bpf flag makes clang emit endian-neutral bytecode; cilium/ebpf
// writes both _bpfel.go (little-endian: amd64, arm64) and _bpfeb.go
// (big-endian: s390x). We use the _bpfel.go output on both x86_64 and arm64.
// The -I flags point at Debian's multiarch locations for <asm/types.h>, which
// lives under /usr/include/<triplet>/asm/ rather than /usr/include/asm/.
// Listing both triplets lets the same generate line work on amd64 and arm64
// build hosts — clang silently ignores include dirs that don't exist.
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -target bpf -cflags "-O2 -g -Wall -Werror -I/usr/include/aarch64-linux-gnu -I/usr/include/x86_64-linux-gnu" sensorBPF ../../bpf/filter.c

// Binary layout mirrors struct capture_event in bpf/filter.c.
const (
	evHdrLen    = 4 + 4 + 1 + 3 // len + ifindex + ingress + pad
	evDataLen   = 1536
	evTotalSize = evHdrLen + evDataLen
)

type TCBPF struct {
	objs   sensorBPFObjects
	links  []link.Link
	rb     *ringbuf.Reader
	rbOnce sync.Once
	ifaces map[int]string // ifindex -> name

	captured atomic.Uint64
	closed   sync.Once
}

func (t *TCBPF) closeRB() error {
	var err error
	t.rbOnce.Do(func() {
		if t.rb != nil {
			err = t.rb.Close()
		}
	})
	return err
}

func NewTCBPF() (*TCBPF, error) {
	if err := rlimit.RemoveMemlock(); err != nil {
		return nil, fmt.Errorf("remove memlock: %w", err)
	}
	t := &TCBPF{ifaces: make(map[int]string)}
	if err := loadSensorBPFObjects(&t.objs, nil); err != nil {
		return nil, fmt.Errorf("load bpf objects: %w", err)
	}
	return t, nil
}

func (t *TCBPF) Mode() string { return "tcbpf" }

func (t *TCBPF) Start(ctx context.Context, ifaces []string) (<-chan Packet, error) {
	for _, name := range ifaces {
		l, err := net.InterfaceByName(name)
		if err != nil {
			slog.Warn("interface not found, skipping", "iface", name, "err", err)
			continue
		}
		if err := t.attach(l); err != nil {
			slog.Warn("attach failed, skipping", "iface", name, "err", err)
			continue
		}
		t.ifaces[l.Index] = l.Name
	}
	if len(t.ifaces) == 0 {
		return nil, errors.New("tcbpf: no interfaces attached")
	}

	rb, err := ringbuf.NewReader(t.objs.Events)
	if err != nil {
		return nil, fmt.Errorf("ringbuf reader: %w", err)
	}
	t.rb = rb

	// rb.Read() blocks with no deadline. On a quiet node ctx cancellation
	// would never unblock it — closing the reader makes Read() return
	// ErrClosed so reader() can exit.
	go func() {
		<-ctx.Done()
		_ = t.closeRB()
	}()

	out := make(chan Packet, 1024)
	go t.reader(ctx, out)
	return out, nil
}

func (t *TCBPF) attach(l *net.Interface) error {
	if _, err := netlink.LinkByIndex(l.Index); err != nil {
		return fmt.Errorf("netlink lookup: %w", err)
	}
	qdisc := &netlink.GenericQdisc{
		QdiscAttrs: netlink.QdiscAttrs{
			LinkIndex: l.Index,
			Parent:    netlink.HANDLE_CLSACT,
			Handle:    netlink.MakeHandle(0xffff, 0),
		},
		QdiscType: "clsact",
	}
	if err := netlink.QdiscReplace(qdisc); err != nil {
		return fmt.Errorf("qdisc clsact: %w", err)
	}

	ingress, err := link.AttachTCX(link.TCXOptions{
		Interface: l.Index,
		Program:   t.objs.SensorIngress,
		Attach:    ebpf.AttachTCXIngress,
	})
	if err != nil {
		return fmt.Errorf("attach ingress: %w", err)
	}
	egress, err := link.AttachTCX(link.TCXOptions{
		Interface: l.Index,
		Program:   t.objs.SensorEgress,
		Attach:    ebpf.AttachTCXEgress,
	})
	if err != nil {
		_ = ingress.Close()
		return fmt.Errorf("attach egress: %w", err)
	}
	t.links = append(t.links, ingress, egress)
	return nil
}

func (t *TCBPF) reader(ctx context.Context, out chan<- Packet) {
	defer close(out)
	for {
		rec, err := t.rb.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				return
			}
			slog.Warn("ringbuf read", "err", err)
			continue
		}
		if len(rec.RawSample) < evHdrLen {
			continue
		}
		wireLen := binary.LittleEndian.Uint32(rec.RawSample[0:4])
		ifindex := binary.LittleEndian.Uint32(rec.RawSample[4:8])
		ingress := rec.RawSample[8] == 1

		payloadLen := int(wireLen)
		if payloadLen > evDataLen {
			payloadLen = evDataLen
		}
		if evHdrLen+payloadLen > len(rec.RawSample) {
			payloadLen = len(rec.RawSample) - evHdrLen
		}
		pkt := Packet{
			Data:  rec.RawSample[evHdrLen : evHdrLen+payloadLen],
			Iface: t.ifaces[int(ifindex)],
		}
		if ingress {
			pkt.Direction = DirIngress
		} else {
			pkt.Direction = DirEgress
		}
		t.captured.Add(1)
		select {
		case out <- pkt:
		case <-ctx.Done():
			return
		}
	}
}

func (t *TCBPF) Stats() Stats {
	fd := make(map[string]uint64, len(filter.AllReasons))
	for i, r := range filter.AllReasons {
		fd[string(r)] = t.readDropCounter(uint32(i))
	}
	return Stats{
		CapturedPackets: t.captured.Load(),
		KernelDrops:     t.readDropCounter(dropRBFullIndex),
		FilterDrops:     fd,
	}
}

// readDropCounter sums the per-CPU BPF counter array at the given index.
// Returns 0 if the map is not loaded or the lookup fails.
func (t *TCBPF) readDropCounter(idx uint32) uint64 {
	if t.objs.DropCounters == nil {
		return 0
	}
	var per []uint64
	if err := t.objs.DropCounters.Lookup(idx, &per); err != nil {
		return 0
	}
	var v uint64
	for _, c := range per {
		v += c
	}
	return v
}

func (t *TCBPF) Close() error {
	var firstErr error
	t.closed.Do(func() {
		if err := t.closeRB(); err != nil && firstErr == nil {
			firstErr = err
		}
		for _, l := range t.links {
			if err := l.Close(); err != nil && firstErr == nil {
				firstErr = err
			}
		}
		if err := t.objs.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
	})
	return firstErr
}
