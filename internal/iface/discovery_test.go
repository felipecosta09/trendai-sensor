package iface

import "testing"

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
