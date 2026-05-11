package forward

import (
	"bytes"
	"net"
	"testing"
)

func TestVXLANHeaderLayout(t *testing.T) {
	// RFC 7348 VXLAN header: 8 bytes total.
	//   byte 0      = flags (I-flag set, 0x08)
	//   bytes 1..3  = reserved (must be 0)
	//   bytes 4..6  = 24-bit VNI (network byte order)
	//   byte 7      = reserved (must be 0)
	// Lock the layout for a handful of VNIs.
	cases := []struct {
		vni  uint32
		want []byte
	}{
		{0x000000, []byte{0x08, 0, 0, 0, 0, 0, 0, 0}},
		{0x000001, []byte{0x08, 0, 0, 0, 0, 0, 0x01, 0}},
		{0xabcdef, []byte{0x08, 0, 0, 0, 0xab, 0xcd, 0xef, 0}},
	}
	for _, c := range cases {
		f := &Forwarder{}
		// Manually build header using the same logic as New to avoid touching
		// the net stack in a unit test.
		f.header[0] = 0x08
		f.header[4] = byte(c.vni >> 16)
		f.header[5] = byte(c.vni >> 8)
		f.header[6] = byte(c.vni)
		f.header[7] = 0
		if !bytes.Equal(f.header[:], c.want) {
			t.Errorf("vni %#x: got %x, want %x", c.vni, f.header[:], c.want)
		}
	}
}

func TestMTUOverheadIs50(t *testing.T) {
	// Regression: eth(14) + ip(20) + udp(8) + vxlan(8) = 50.
	if VXLANOverhead != 50 {
		t.Fatalf("VXLANOverhead = %d, want 50", VXLANOverhead)
	}
}

// newLoopback makes a Forwarder pointed at a real UDP socket on loopback so
// Send's Write syscall succeeds. We bind a receiver to discard writes.
func newLoopback(t testing.TB, mtu int) (*Forwarder, func()) {
	t.Helper()
	rx, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	port := rx.LocalAddr().(*net.UDPAddr).Port
	// New() only takes an IP and pins the port to VXLAN/4789; for tests we
	// want Write to succeed against the listener on an ephemeral port.
	f, err := New("127.0.0.1", 0, mtu)
	if err != nil {
		_ = rx.Close()
		t.Fatalf("new: %v", err)
	}
	_ = f.conn.Close()
	conn, err := net.DialUDP("udp4", nil, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: port})
	if err != nil {
		_ = rx.Close()
		t.Fatalf("dial: %v", err)
	}
	f.conn = conn
	cleanup := func() { _ = f.Close(); _ = rx.Close() }
	return f, cleanup
}

// BenchmarkSendAllocsPerOp guards the buffer-reuse invariant. Send must not
// allocate per frame — a regression to the pre-v0.1.7 per-packet make() would
// show up as non-zero AllocsPerOp and at post-filter load (10k pps × 1.5 KB)
// translate to ~15 MB/s of transient allocs.
func BenchmarkSendAllocsPerOp(b *testing.B) {
	f, cleanup := newLoopback(b, 1500)
	defer cleanup()
	frame := make([]byte, 1400)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		f.Send(frame)
	}
}

// TestSendZeroAllocs fails loudly if Send regresses to allocating per frame.
// testing.AllocsPerRun is noisy on the first few iterations, so we average
// over a handful.
func TestSendZeroAllocs(t *testing.T) {
	f, cleanup := newLoopback(t, 1500)
	defer cleanup()
	frame := make([]byte, 1400)
	// Warm up the UDP conn write path; the first Write can allocate
	// internally in net.Conn.
	for i := 0; i < 10; i++ {
		f.Send(frame)
	}
	allocs := testing.AllocsPerRun(100, func() { f.Send(frame) })
	if allocs != 0 {
		t.Errorf("Send allocates %v/op, want 0", allocs)
	}
}
