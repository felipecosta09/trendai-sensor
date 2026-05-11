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
	objs     sensorBPFObjects
	linksMu  sync.RWMutex
	links    map[int][]link.Link // ifindex -> [ingressLink, egressLink]
	rb       *ringbuf.Reader
	rbOnce   sync.Once
	readerWG sync.WaitGroup
	ifaces   map[int]string // ifindex -> name

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
	t := &TCBPF{ifaces: make(map[int]string), links: make(map[int][]link.Link)}
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
	}
	t.linksMu.RLock()
	count := len(t.ifaces)
	t.linksMu.RUnlock()
	if count == 0 {
		slog.Warn("tcbpf: no interfaces attached, waiting for dynamic attach")
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
	t.readerWG.Add(1)
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
	t.linksMu.Lock()
	t.links[l.Index] = []link.Link{ingress, egress}
	t.ifaces[l.Index] = l.Name
	t.linksMu.Unlock()
	return nil
}

func (t *TCBPF) reader(ctx context.Context, out chan<- Packet) {
	defer t.readerWG.Done()
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
		t.linksMu.RLock()
		ifaceName := t.ifaces[int(ifindex)]
		t.linksMu.RUnlock()
		pkt := Packet{
			Data:  rec.RawSample[evHdrLen : evHdrLen+payloadLen],
			Iface: ifaceName,
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

func (t *TCBPF) Attach(iface string) error {
	l, err := net.InterfaceByName(iface)
	if err != nil {
		slog.Debug("tcbpf attach: interface not found, may be gone", "iface", iface, "err", err)
		return nil
	}
	t.linksMu.RLock()
	_, already := t.links[l.Index]
	t.linksMu.RUnlock()
	if already {
		return nil
	}
	return t.attach(l)
}

func (t *TCBPF) Detach(iface string) error {
	l, err := net.InterfaceByName(iface)
	if err != nil {
		slog.Debug("tcbpf detach: interface not found, may be gone", "iface", iface, "err", err)
		return nil
	}
	t.linksMu.Lock()
	ls, ok := t.links[l.Index]
	if !ok {
		t.linksMu.Unlock()
		return nil
	}
	delete(t.links, l.Index)
	delete(t.ifaces, l.Index)
	t.linksMu.Unlock()
	for _, lk := range ls {
		if err := lk.Close(); err != nil {
			slog.Warn("tcbpf detach: close link", "iface", iface, "err", err)
		}
	}
	return nil
}

func (t *TCBPF) Close() error {
	var firstErr error
	t.closed.Do(func() {
		if err := t.closeRB(); err != nil && firstErr == nil {
			firstErr = err
		}
		// Wait for reader() to drain the ring buffer and exit before closing
		// the BPF objects — accessing t.objs after Close() is a use-after-free.
		t.readerWG.Wait()
		t.linksMu.Lock()
		for _, ls := range t.links {
			for _, l := range ls {
				if err := l.Close(); err != nil && firstErr == nil {
					firstErr = err
				}
			}
		}
		// Clear maps so a post-close Detach (e.g. a watcher RTM_DELLINK event
		// racing with shutdown) finds nothing and skips the now-invalid handles.
		t.links = make(map[int][]link.Link)
		t.ifaces = make(map[int]string)
		t.linksMu.Unlock()
		if err := t.objs.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
	})
	return firstErr
}
