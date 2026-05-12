package iface

import "testing"

func TestIsPodVeth(t *testing.T) {
	cases := []struct {
		name string
		want bool
	}{
		// EKS aws-vpc-cni
		{"eni1abc2def", true},
		{"eni0", true},
		// Azure CNI
		{"azv1a2b3c", true},
		// kubenet / generic veth
		{"veth1234abcd", true},
		{"vethXYZ", true},
		// Calico non-eBPF
		{"cali12345abcde", true},
		// Cilium — lxc* is intentionally excluded
		{"lxcabcd1234", false},
		// Physical NICs — must not match
		{"eth0", false},
		{"ens3", false},
		{"enp0s8", false},
		{"eno1", false},
		// Substring must not match (HasPrefix only)
		{"myeni", false},
		{"notazv", false},
		{"test-veth", false},
		// Empty
		{"", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := IsPodVeth(tc.name); got != tc.want {
				t.Errorf("IsPodVeth(%q) = %v, want %v", tc.name, got, tc.want)
			}
		})
	}
}

func TestShouldSkip(t *testing.T) {
	cases := []struct {
		name string
		skip bool
	}{
		// Real capture-worthy interfaces.
		{"eth0", false},
		{"eth1", false},
		{"ens3", false},
		{"enp0s8", false},
		{"bond0", false},
		{"wlan0", false},

		// Loopback.
		{"lo", true},

		// CNI / container bridges.
		{"veth1234abcd", true},
		{"vethXYZ", true},
		{"br-a1b2c3d4", true},
		{"docker0", true},
		{"cali12345abcde", true},
		{"cni0", true},
		{"flannel.1", true},
		{"weave", true},
		{"tunl0", true},

		// Modern CNI / kube-proxy helpers that pre-v0.1.7 captured twice.
		{"azv1a2b3c", true},    // Azure CNI per-pod vNIC
		{"lxc3def", true},      // Cilium per-pod endpoint
		{"eni1abc", true},      // AWS VPC CNI routed mode
		{"kube-ipvs0", true},   // kube-proxy IPVS dummy
		{"dummy0", true},       // generic dummy / bonding helpers

		// Must not regress physical-NIC naming — they start with "eth"/
		// "ens"/"enp"/"eno", none of which collide with "eni".
		{"eth0", false},
		{"eno1", false},

		// Edge cases: substring match must NOT trigger — HasPrefix only.
		{"myveth", false},
		{"test-br-0", false},
		{"notdocker", false},

		// Empty name — shouldn't match any prefix.
		{"", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := shouldSkip(tc.name); got != tc.skip {
				t.Errorf("shouldSkip(%q) = %v, want %v", tc.name, got, tc.skip)
			}
		})
	}
}
