// Package iface lists the host interfaces this sensor should capture on.
// Skips virtual, CNI, and docker bridges so we don't see the same packet
// twice via per-pod veth pairs.
package iface

import (
	"net"
	"strings"
)

// skipPrefixes are interface-name prefixes to exclude from capture. These
// correspond to per-pod veths and CNI bridges that would cause us to see the
// same packet twice.
//
// Prefix coverage by CNI (as of 2026):
//
//	veth, cni, br-, docker, flannel, weave, tunl — classic / default
//	cali                                          — Calico
//	azv                                           — Azure CNI (per-pod vNIC)
//	lxc                                           — Cilium (per-pod endpoint)
//	eni                                           — AWS VPC CNI in routed /
//	                                                prefix-delegation mode
//	kube-ipvs0, dummy                             — kube-proxy IPVS & generic
//	                                                dummy / bonding helpers
//
// "eni" does not collide with "eth*"/"ens*"/"enp*"/"eno*" (physical NIC
// naming conventions on Linux) — HasPrefix is exact on the three-byte
// boundary.
var skipPrefixes = []string{
	"veth", "br-", "docker", "cali", "cni", "flannel", "lo", "tunl", "weave",
	"azv", "lxc", "eni", "kube-ipvs0", "dummy",
}

// List returns the set of interface names that should be captured. It mirrors
// the ordering of net.Interfaces() so tests are deterministic.
func List() ([]string, error) {
	all, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	var out []string
	for _, i := range all {
		if i.Flags&net.FlagUp == 0 {
			continue
		}
		if shouldSkip(i.Name) {
			continue
		}
		out = append(out, i.Name)
	}
	return out, nil
}

func shouldSkip(name string) bool {
	for _, p := range skipPrefixes {
		if strings.HasPrefix(name, p) {
			return true
		}
	}
	return false
}

// podVethPrefixes are the host-side veth interface name prefixes for the CNIs
// that support kernel-level veth capture. Cilium (lxc*) is intentionally
// absent — its eBPF datapath may redirect packets before veth traversal.
var podVethPrefixes = []string{"veth", "eni", "azv", "cali"}

// IsPodVeth reports whether name is a CNI pod-veth interface.
func IsPodVeth(name string) bool {
	for _, p := range podVethPrefixes {
		if strings.HasPrefix(name, p) {
			return true
		}
	}
	return false
}

// ListPodVeths returns the names of all UP interfaces whose names match a
// pod-veth prefix. Called at startup for the initial set; the watcher handles
// subsequent additions.
func ListPodVeths() ([]string, error) {
	all, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	var out []string
	for _, i := range all {
		if i.Flags&net.FlagUp == 0 {
			continue
		}
		if IsPodVeth(i.Name) {
			out = append(out, i.Name)
		}
	}
	return out, nil
}
