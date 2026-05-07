package filter

import (
	"encoding/binary"
	"testing"

	"golang.org/x/net/bpf"
)

// buildFrame constructs a minimal Eth+IPv4(+TCP/UDP) frame for testing.
func buildFrame(ethertype uint16, proto uint8, dst [4]byte, sport, dport uint16) []byte {
	return buildFrameSrc(ethertype, proto, [4]byte{10, 0, 0, 1}, dst, sport, dport)
}

// buildFrameSrc is the src-aware variant used for tests that care about the
// source IP (e.g. metadata response leak).
func buildFrameSrc(ethertype uint16, proto uint8, src, dst [4]byte, sport, dport uint16) []byte {
	f := make([]byte, 14+20+8)
	binary.BigEndian.PutUint16(f[12:14], ethertype)
	f[14] = 0x45 // version 4, IHL 5
	f[23] = proto
	copy(f[26:30], src[:])
	copy(f[30:34], dst[:])
	binary.BigEndian.PutUint16(f[34:36], sport)
	binary.BigEndian.PutUint16(f[36:38], dport)
	return f
}

func TestAssembleKnownCases(t *testing.T) {
	spec := Default()
	prog, err := Assemble(spec)
	if err != nil {
		t.Fatalf("assemble: %v", err)
	}
	vm, err := bpf.NewVM(prog)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}

	cases := []struct {
		name   string
		frame  []byte
		accept bool
	}{
		{"tcp 80", buildFrame(0x0800, 6, [4]byte{10, 0, 0, 5}, 40000, 80), true},
		{"tcp 443", buildFrame(0x0800, 6, [4]byte{10, 0, 0, 5}, 40000, 443), true},
		{"udp 4789 (vxlan dst)", buildFrame(0x0800, 17, [4]byte{10, 0, 0, 5}, 40000, 4789), false},
		{"udp 16401 (vxlan src)", buildFrame(0x0800, 17, [4]byte{10, 0, 0, 5}, 16401, 9999), false},
		{"udp 53 src", buildFrame(0x0800, 17, [4]byte{10, 0, 0, 5}, 53, 40000), false},
		{"udp 53 dst", buildFrame(0x0800, 17, [4]byte{10, 0, 0, 5}, 40000, 53), false},
		{"metadata dst", buildFrame(0x0800, 6, [4]byte{169, 254, 169, 254}, 40000, 80), false},
		{"metadata src (imds response)", buildFrameSrc(0x0800, 6, [4]byte{169, 254, 169, 254}, [4]byte{10, 0, 0, 5}, 80, 40000), false},
		{"ipv6 (arp)", buildFrame(0x86dd, 6, [4]byte{10, 0, 0, 5}, 40000, 80), false},
		{"icmp", buildFrame(0x0800, 1, [4]byte{10, 0, 0, 5}, 0, 0), false},
		{"udp ok", buildFrame(0x0800, 17, [4]byte{10, 0, 0, 5}, 40000, 443), true},
		// k8s-noise: TCP, dst port
		{"tcp ssh dst", buildFrame(0x0800, 6, [4]byte{10, 0, 0, 5}, 40000, 22), false},
		{"tcp sensor-health dst", buildFrame(0x0800, 6, [4]byte{10, 0, 0, 5}, 40000, 8080), false},
		{"tcp sensor-metrics dst", buildFrame(0x0800, 6, [4]byte{10, 0, 0, 5}, 40000, 9090), false},
		{"tcp kubelet dst", buildFrame(0x0800, 6, [4]byte{10, 0, 0, 5}, 40000, 10250), false},
		{"tcp kproxy-healthz dst", buildFrame(0x0800, 6, [4]byte{10, 0, 0, 5}, 40000, 10256), false},
		{"tcp coredns-ready dst", buildFrame(0x0800, 6, [4]byte{10, 0, 0, 5}, 40000, 8181), false},
		{"tcp coredns-ready src", buildFrame(0x0800, 6, [4]byte{10, 0, 0, 5}, 8181, 40000), false},
		// k8s-noise: TCP, src port (mirrored return half)
		{"tcp ssh src", buildFrame(0x0800, 6, [4]byte{10, 0, 0, 5}, 22, 40000), false},
		{"tcp kubelet src", buildFrame(0x0800, 6, [4]byte{10, 0, 0, 5}, 10250, 40000), false},
		// k8s-noise: UDP NTP (src or dst)
		{"udp ntp dst", buildFrame(0x0800, 17, [4]byte{10, 0, 0, 5}, 40000, 123), false},
		{"udp ntp src", buildFrame(0x0800, 17, [4]byte{10, 0, 0, 5}, 123, 40000), false},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			out, err := vm.Run(c.frame)
			if err != nil {
				t.Fatalf("run: %v", err)
			}
			accepted := out != 0
			if accepted != c.accept {
				t.Errorf("got accepted=%v, want %v (ret=%d)", accepted, c.accept, out)
			}
		})
	}
}

// Assemble must refuse to emit a truncated program when the port lists grow
// past what a uint8 skip can encode. The exact threshold depends on the fixed
// prefix size; a 150-port list is comfortably over it.
func TestAssembleRejectsOversizedProgram(t *testing.T) {
	spec := Default()
	spec.K8sNoiseTCPPorts = make([]uint16, 150)
	for i := range spec.K8sNoiseTCPPorts {
		spec.K8sNoiseTCPPorts[i] = uint16(30000 + i)
	}
	if _, err := Assemble(spec); err == nil {
		t.Fatalf("expected error for oversized program, got nil")
	}
}
