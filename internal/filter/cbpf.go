package filter

import (
	"encoding/binary"

	"golang.org/x/net/bpf"
)

// Ethernet + IPv4 offsets. Indexing into the L4 header uses the "X = IHL*4"
// idiom (LoadMemShift) so IP options don't throw off UDP port offsets.
const (
	offEthertype = 12
	offIPProto   = 23 // 14 + 9
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
// Program order (drop early, cheap checks first):
//
//	ethertype == IPv4          else drop
//	ip.dst    != metadata      else drop
//	ip.proto == TCP            -> accept
//	ip.proto == UDP            else drop
//	udp.sport not in {53, 16401}
//	udp.dport not in {53, 4789}
//	-> accept
func Assemble(spec Spec) []bpf.Instruction {
	metadata := binary.BigEndian.Uint32(spec.MetadataIP[:])
	dns := uint32(spec.DNSPort)
	vxDst := uint32(spec.VXLANPort)
	vxSrc := uint32(spec.VXLANSrcPort)

	var p []bpf.Instruction
	var drops []int // indices of JumpIf instructions whose true-branch is DROP

	jumpDrop := func(inst bpf.JumpIf) {
		drops = append(drops, len(p))
		p = append(p, inst)
	}

	p = append(p, bpf.LoadAbsolute{Off: offEthertype, Size: 2})
	jumpDrop(bpf.JumpIf{Cond: bpf.JumpNotEqual, Val: ethIPv4})

	p = append(p, bpf.LoadAbsolute{Off: offIPDst, Size: 4})
	jumpDrop(bpf.JumpIf{Cond: bpf.JumpEqual, Val: metadata})

	p = append(p, bpf.LoadAbsolute{Off: offIPProto, Size: 1})

	tcpJmp := len(p)
	p = append(p, bpf.JumpIf{Cond: bpf.JumpEqual, Val: protoTCP}) // -> accept
	jumpDrop(bpf.JumpIf{Cond: bpf.JumpNotEqual, Val: protoUDP})

	p = append(p, bpf.LoadMemShift{Off: offIHL}) // X = IHL*4
	p = append(p, bpf.LoadIndirect{Off: ethLen, Size: 2})
	jumpDrop(bpf.JumpIf{Cond: bpf.JumpEqual, Val: dns})
	jumpDrop(bpf.JumpIf{Cond: bpf.JumpEqual, Val: vxSrc})
	p = append(p, bpf.LoadIndirect{Off: ethLen + 2, Size: 2})
	jumpDrop(bpf.JumpIf{Cond: bpf.JumpEqual, Val: dns})
	jumpDrop(bpf.JumpIf{Cond: bpf.JumpEqual, Val: vxDst})

	acceptIdx := len(p)
	p = append(p, bpf.RetConstant{Val: acceptRet})
	dropIdx := len(p)
	p = append(p, bpf.RetConstant{Val: dropRet})

	for _, site := range drops {
		ji := p[site].(bpf.JumpIf)
		ji.SkipTrue = uint8(dropIdx - site - 1)
		p[site] = ji
	}
	if ji, ok := p[tcpJmp].(bpf.JumpIf); ok {
		ji.SkipTrue = uint8(acceptIdx - tcpJmp - 1)
		p[tcpJmp] = ji
	}
	return p
}
