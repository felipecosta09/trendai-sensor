// Package forward builds VXLAN packets and sends them to the NDR appliance.
package forward

import (
	"encoding/binary"
	"fmt"
	"net"
	"sync/atomic"
)

// VXLAN overhead when encapsulating over IPv4:
//
//	outer Ethernet (14) + outer IPv4 (20) + outer UDP (8) + VXLAN (8) = 50
//
// The outer Ethernet is added by the kernel; our UDP socket gives us IP+UDP
// but we account for the full path here since the bottleneck is the link MTU
// between the node and the NDR.
const VXLANOverhead = 50

// Forwarder wraps a UDP socket to the NDR with a reusable VXLAN header.
//
// Send is called from a single goroutine (the main packet loop in
// cmd/sensor/main.go ranges over the capture channel). buf is a reusable
// scratch slice sized at innerMax+8 so each Send does one copy+Write
// instead of allocating a fresh []byte per frame. If Forwarder ever gets
// used from multiple goroutines this needs a mutex or sync.Pool.
type Forwarder struct {
	conn     *net.UDPConn
	header   [8]byte
	dst      *net.UDPAddr
	innerMax int
	buf      []byte

	sent        atomic.Uint64
	sendErrors  atomic.Uint64
	mtuExceeded atomic.Uint64
	bytesOut    atomic.Uint64
}

// New creates a forwarder sending to ndrAddr:4789 with the given VNI.
// ndrMTU is the link MTU to the NDR (default 1500). Packets larger than
// ndrMTU - VXLANOverhead are dropped with a counter bump rather than
// silently fragmented.
func New(ndrAddr string, vni uint32, ndrMTU int) (*Forwarder, error) {
	if vni&0xff000000 != 0 {
		return nil, fmt.Errorf("vni %#x out of range", vni)
	}
	ip := net.ParseIP(ndrAddr)
	if ip == nil {
		return nil, fmt.Errorf("invalid NDR address %q", ndrAddr)
	}
	dst := &net.UDPAddr{IP: ip, Port: 4789}
	conn, err := net.DialUDP("udp4", nil, dst)
	if err != nil {
		return nil, fmt.Errorf("dial NDR: %w", err)
	}

	var hdr [8]byte
	// Flags byte: I (instance) bit set = VNI valid.
	binary.BigEndian.PutUint32(hdr[0:4], 0x08000000)
	// VNI occupies the upper 24 bits of the second word.
	binary.BigEndian.PutUint32(hdr[4:8], vni<<8)

	innerMax := ndrMTU - VXLANOverhead
	f := &Forwarder{
		conn:     conn,
		header:   hdr,
		dst:      dst,
		innerMax: innerMax,
		buf:      make([]byte, innerMax+8),
	}
	copy(f.buf[:8], f.header[:])
	return f, nil
}

// Send encapsulates one frame and writes it to the NDR. Returns the number
// of inner bytes forwarded (0 if the packet was dropped).
func (f *Forwarder) Send(frame []byte) int {
	if len(frame) > f.innerMax {
		f.mtuExceeded.Add(1)
		return 0
	}
	// f.buf[:8] holds the VXLAN header written once in New and never mutated
	// afterwards — skip re-copying it every frame.
	n := copy(f.buf[8:8+len(frame)], frame)
	written, err := f.conn.Write(f.buf[:8+n])
	if err != nil {
		f.sendErrors.Add(1)
		return 0
	}
	f.sent.Add(1)
	f.bytesOut.Add(uint64(written))
	return len(frame)
}

// Stats returns a snapshot of forwarder counters.
type Stats struct {
	Sent        uint64
	SendErrors  uint64
	MTUExceeded uint64
	BytesOut    uint64
}

func (f *Forwarder) Stats() Stats {
	return Stats{
		Sent:        f.sent.Load(),
		SendErrors:  f.sendErrors.Load(),
		MTUExceeded: f.mtuExceeded.Load(),
		BytesOut:    f.bytesOut.Load(),
	}
}

func (f *Forwarder) Close() error { return f.conn.Close() }
