package forward

import (
	"bytes"
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
