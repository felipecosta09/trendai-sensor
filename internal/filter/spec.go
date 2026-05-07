// Package filter holds the single source of truth for which packets are
// dropped before forwarding to the NDR. Both the TC-BPF program (kernel) and
// the AF_PACKET fallback (cBPF) derive their behavior from this spec so the
// two paths cannot drift.
package filter

// Spec is the set of drop rules applied to every captured frame.
type Spec struct {
	MetadataIP   [4]byte
	DNSPort      uint16
	VXLANPort    uint16
	VXLANSrcPort uint16
	// K8sNoiseTCPPorts matches either src OR dst TCP port — mirrored return
	// traffic would otherwise slip through a dst-only rule.
	K8sNoiseTCPPorts []uint16
	// K8sNoiseUDPPorts is the UDP counterpart (src OR dst).
	K8sNoiseUDPPorts []uint16
	IPv4Only         bool
	TCPUDPOnly       bool
}

// Default returns the standard drop rules: IPv4-only, TCP/UDP-only, drop DNS,
// drop cloud-provider metadata-service traffic, drop our own outbound VXLAN
// so the sensor doesn't loop on its own forwarded frames, and drop well-known
// cluster plumbing chatter (kubelet/kube-proxy probes, sensor self, NTP, SSH)
// so Vision One only sees workload traffic.
func Default() Spec {
	return Spec{
		MetadataIP:   [4]byte{169, 254, 169, 254},
		DNSPort:      53,
		VXLANPort:    4789,
		VXLANSrcPort: 16401,
		K8sNoiseTCPPorts: []uint16{
			22,    // SSH (bastion/admin)
			8080,  // sensor health + common k8s liveness probe port
			8181,  // CoreDNS ready endpoint (kube-probe hits every 5s per node)
			9090,  // sensor metrics + Prometheus scrape
			10249, // kube-proxy metrics
			10250, // kubelet API
			10255, // kubelet read-only (legacy)
			10256, // kube-proxy healthz
		},
		K8sNoiseUDPPorts: []uint16{
			123, // NTP
		},
		IPv4Only:   true,
		TCPUDPOnly: true,
	}
}

// DropReason labels filter-side drops for metrics cardinality. Ordering
// matches the BPF-side enum in bpf/filter.c (DROP_NON_IPV4=0, DROP_METADATA=1,
// DROP_NON_L4=2, DROP_DNS=3, DROP_VXLAN=4, DROP_TRUNC=5, DROP_K8S_NOISE=6)
// so the same index can be used to read the BPF drop_counters map.
type DropReason string

const (
	DropNonIPv4   DropReason = "non_ipv4"
	DropMetadata  DropReason = "metadata"
	DropNonL4     DropReason = "non_tcp_udp"
	DropDNS       DropReason = "dns"
	DropVXLAN     DropReason = "vxlan_self"
	DropTruncate  DropReason = "truncated"
	DropK8sNoise  DropReason = "k8s_noise"
)

// AllReasons is used to pre-register Prometheus label series for the
// sensor_packets_dropped_filter_total counter. Order matches the BPF enum.
//
// Ringbuffer-full drops are exported via sensor_packets_dropped_kernel_total,
// not as a filter reason. MTU-exceeded drops are exported via
// sensor_mtu_exceeded_total (forward-layer counter, not a filter reason).
var AllReasons = []DropReason{
	DropNonIPv4, DropMetadata, DropNonL4, DropDNS, DropVXLAN, DropTruncate, DropK8sNoise,
}
