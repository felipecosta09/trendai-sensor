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
	IPv4Only     bool
	TCPUDPOnly   bool
}

// Default returns the standard drop rules: IPv4-only, TCP/UDP-only, drop DNS,
// drop cloud-provider metadata-service traffic, and drop our own outbound
// VXLAN so the sensor doesn't loop on its own forwarded frames.
func Default() Spec {
	return Spec{
		MetadataIP:   [4]byte{169, 254, 169, 254},
		DNSPort:      53,
		VXLANPort:    4789,
		VXLANSrcPort: 16401,
		IPv4Only:     true,
		TCPUDPOnly:   true,
	}
}

// DropReason labels filter-side drops for metrics cardinality. Ordering
// matches the BPF-side enum in bpf/filter.c (DROP_NON_IPV4=0, DROP_METADATA=1,
// DROP_NON_L4=2, DROP_DNS=3, DROP_VXLAN=4, DROP_TRUNC=5) so the same index
// can be used to read the BPF drop_counters map.
type DropReason string

const (
	DropNonIPv4  DropReason = "non_ipv4"
	DropMetadata DropReason = "metadata"
	DropNonL4    DropReason = "non_tcp_udp"
	DropDNS      DropReason = "dns"
	DropVXLAN    DropReason = "vxlan_self"
	DropTruncate DropReason = "truncated"
)

// AllReasons is used to pre-register Prometheus label series for the
// sensor_packets_dropped_filter_total counter. Order matches the BPF enum.
//
// Ringbuffer-full drops are exported via sensor_packets_dropped_kernel_total,
// not as a filter reason. MTU-exceeded drops are exported via
// sensor_mtu_exceeded_total (forward-layer counter, not a filter reason).
var AllReasons = []DropReason{
	DropNonIPv4, DropMetadata, DropNonL4, DropDNS, DropVXLAN, DropTruncate,
}
