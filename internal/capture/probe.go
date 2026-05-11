//go:build linux

package capture

import (
	"fmt"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/features"
)

// ModePreference picks a Capturer. If preferred is "tcbpf" or "afpacket" it is
// honored when supported; "auto" picks TC-BPF when the kernel has the
// required features, AF_PACKET otherwise.
func Pick(preferred string) (string, error) {
	switch preferred {
	case "tcbpf":
		if err := probeTCBPF(); err != nil {
			return "", fmt.Errorf("tcbpf unsupported on this kernel: %w", err)
		}
		return "tcbpf", nil
	case "afpacket":
		return "afpacket", nil
	case "", "auto":
		if err := probeTCBPF(); err != nil {
			// Fallback is the whole point of auto-mode; the probe error is
			// informational, not a failure the caller should surface.
			return "afpacket", nil //nolint:nilerr
		}
		return "tcbpf", nil
	default:
		return "", fmt.Errorf("unknown capture mode %q", preferred)
	}
}

// probeTCBPF returns nil if ringbuf and SCHED_CLS program type are available.
func probeTCBPF() error {
	if err := features.HaveMapType(ebpf.RingBuf); err != nil {
		return fmt.Errorf("ringbuf map: %w", err)
	}
	if err := features.HaveProgramType(ebpf.SchedCLS); err != nil {
		return fmt.Errorf("sched_cls program: %w", err)
	}
	return nil
}
