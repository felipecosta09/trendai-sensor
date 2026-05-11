// Package capture abstracts packet sources (TC-BPF, AF_PACKET). Implementations
// deliver frames to a channel so the forwarder doesn't care which kernel
// feature is in use.
package capture

import "context"

// Direction tags packets for metrics.
type Direction uint8

const (
	DirIngress Direction = iota
	DirEgress
	DirUnknown
)

func (d Direction) String() string {
	switch d {
	case DirIngress:
		return "ingress"
	case DirEgress:
		return "egress"
	default:
		return "unknown"
	}
}

// Packet is a single captured frame plus metadata. Data is valid only until
// the next Recv — callers must copy if they need to keep it.
type Packet struct {
	Data      []byte
	Iface     string
	Direction Direction
}

// Stats describes kernel/driver drop counters.
type Stats struct {
	CapturedPackets uint64
	KernelDrops     uint64
	FilterDrops     map[string]uint64 // reason -> count
}

// Capturer is implemented by tcbpf.go and afpacket.go.
type Capturer interface {
	// Start attaches to all provided interfaces and begins delivering packets
	// on the returned channel. The channel closes when ctx is cancelled.
	// An empty ifaces slice is allowed; call Attach to add interfaces later.
	Start(ctx context.Context, ifaces []string) (<-chan Packet, error)
	// Attach dynamically adds capture on a single interface after Start.
	// Safe to call from a goroutine concurrent with the event loop. No-op if
	// the interface is already attached.
	Attach(iface string) error
	// Detach removes capture from a single interface. No-op if not attached.
	Detach(iface string) error
	// Stats returns a snapshot of kernel/filter drop counters.
	Stats() Stats
	// Close detaches from all interfaces and releases resources.
	Close() error
	// Mode returns "tcbpf" or "afpacket" for logging/metrics.
	Mode() string
}
