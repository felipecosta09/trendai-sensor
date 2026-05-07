package filter

import (
	"encoding/binary"
	"fmt"

	"golang.org/x/net/bpf"
)

// cbpfMaxSkip is the maximum forward distance a classic-BPF JumpIf can
// encode. The skip fields are uint8; silently truncating a longer distance
// produces a filter that drops valid traffic.
const cbpfMaxSkip = 255

// Ethernet + IPv4 offsets. Indexing into the L4 header uses the "X = IHL*4"
// idiom (LoadMemShift) so IP options don't throw off UDP/TCP port offsets.
const (
	offEthertype = 12
	offIPProto   = 23 // 14 + 9
	offIPSrc     = 26 // 14 + 12
	offIPDst     = 30 // 14 + 16
	offIHL       = 14 // IP version/IHL byte
	ethLen       = 14

	ethIPv4  = 0x0800
	protoTCP = 6
	protoUDP = 17

	acceptRet = 0xFFFFFFFF
	dropRet   = 0
)

// Assemble returns a classic BPF program for SO_ATTACH_FILTER implementing
// Spec. Accepted packets return the whole frame (0xFFFFFFFF); dropped
// packets return 0.
//
// Program layout (drop-early, per-protocol port checks, then accept):
//
//	ethertype == IPv4            else drop
//	ip.src    != metadata        else drop   (catches IMDS responses)
//	ip.dst    != metadata        else drop
//	ip.proto == TCP              -> TCP block
//	ip.proto == UDP              else drop
//	(UDP block)
//	  udp.sport in {DNS, VXLAN-src, NTP}  -> drop
//	  udp.dport in {DNS, VXLAN-dst, NTP}  -> drop
//	  -> accept
//	(TCP block)
//	  tcp.sport in K8sNoiseTCPPorts       -> drop
//	  tcp.dport in K8sNoiseTCPPorts       -> drop
//	  -> accept
func Assemble(spec Spec) ([]bpf.Instruction, error) {
	metadata := binary.BigEndian.Uint32(spec.MetadataIP[:])
	dns := uint32(spec.DNSPort)
	vxDst := uint32(spec.VXLANPort)
	vxSrc := uint32(spec.VXLANSrcPort)

	var p []bpf.Instruction
	var drops []int // indices of JumpIf sites whose true-branch is DROP

	jumpDrop := func(inst bpf.JumpIf) {
		drops = append(drops, len(p))
		p = append(p, inst)
	}

	p = append(p, bpf.LoadAbsolute{Off: offEthertype, Size: 2})
	jumpDrop(bpf.JumpIf{Cond: bpf.JumpNotEqual, Val: ethIPv4})

	p = append(p, bpf.LoadAbsolute{Off: offIPSrc, Size: 4})
	jumpDrop(bpf.JumpIf{Cond: bpf.JumpEqual, Val: metadata})

	p = append(p, bpf.LoadAbsolute{Off: offIPDst, Size: 4})
	jumpDrop(bpf.JumpIf{Cond: bpf.JumpEqual, Val: metadata})

	p = append(p, bpf.LoadAbsolute{Off: offIPProto, Size: 1})

	tcpJmp := len(p)
	p = append(p, bpf.JumpIf{Cond: bpf.JumpEqual, Val: protoTCP}) // -> TCP block
	jumpDrop(bpf.JumpIf{Cond: bpf.JumpNotEqual, Val: protoUDP})

	// --- UDP block ---
	p = append(p, bpf.LoadMemShift{Off: offIHL}) // X = IHL*4
	p = append(p, bpf.LoadIndirect{Off: ethLen, Size: 2})
	jumpDrop(bpf.JumpIf{Cond: bpf.JumpEqual, Val: dns})
	jumpDrop(bpf.JumpIf{Cond: bpf.JumpEqual, Val: vxSrc})
	for _, port := range spec.K8sNoiseUDPPorts {
		jumpDrop(bpf.JumpIf{Cond: bpf.JumpEqual, Val: uint32(port)})
	}
	p = append(p, bpf.LoadIndirect{Off: ethLen + 2, Size: 2})
	jumpDrop(bpf.JumpIf{Cond: bpf.JumpEqual, Val: dns})
	jumpDrop(bpf.JumpIf{Cond: bpf.JumpEqual, Val: vxDst})
	for _, port := range spec.K8sNoiseUDPPorts {
		jumpDrop(bpf.JumpIf{Cond: bpf.JumpEqual, Val: uint32(port)})
	}
	acceptUDPIdx := len(p)
	p = append(p, bpf.RetConstant{Val: acceptRet})

	// --- TCP block ---
	tcpBlockStart := len(p)
	p = append(p, bpf.LoadMemShift{Off: offIHL})
	p = append(p, bpf.LoadIndirect{Off: ethLen, Size: 2})
	for _, port := range spec.K8sNoiseTCPPorts {
		jumpDrop(bpf.JumpIf{Cond: bpf.JumpEqual, Val: uint32(port)})
	}
	p = append(p, bpf.LoadIndirect{Off: ethLen + 2, Size: 2})
	for _, port := range spec.K8sNoiseTCPPorts {
		jumpDrop(bpf.JumpIf{Cond: bpf.JumpEqual, Val: uint32(port)})
	}
	p = append(p, bpf.RetConstant{Val: acceptRet})

	dropIdx := len(p)
	p = append(p, bpf.RetConstant{Val: dropRet})

	// Patch jumps. All drop sites skip forward to dropIdx; tcpJmp jumps forward
	// to the TCP block start. cBPF skip fields are uint8 — silently truncating
	// a longer distance would turn a drop-jump into a no-op and leak noise
	// upstream, so verify every skip fits before returning.
	_ = acceptUDPIdx // silence unused-var if future refactor
	for _, site := range drops {
		dist := dropIdx - site - 1
		if dist > cbpfMaxSkip {
			return nil, fmt.Errorf("cbpf: drop-jump distance %d exceeds uint8 max %d (program too large; trim port lists)", dist, cbpfMaxSkip)
		}
		ji := p[site].(bpf.JumpIf)
		ji.SkipTrue = uint8(dist)
		p[site] = ji
	}
	if ji, ok := p[tcpJmp].(bpf.JumpIf); ok {
		dist := tcpBlockStart - tcpJmp - 1
		if dist > cbpfMaxSkip {
			return nil, fmt.Errorf("cbpf: tcp-block jump distance %d exceeds uint8 max %d (program too large; trim port lists)", dist, cbpfMaxSkip)
		}
		ji.SkipTrue = uint8(dist)
		p[tcpJmp] = ji
	}
	return p, nil
}
