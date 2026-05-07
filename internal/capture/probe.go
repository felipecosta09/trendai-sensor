//go:build linux

package capture

import (
	"errors"
	"fmt"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/features"
)

// ErrUnsupported wraps the reason a requested mode can't be loaded on this
// kernel. Callers can match via errors.Is to distinguish missing-kernel-feature
// failures from config-validation errors (e.g. an unknown mode string).
var ErrUnsupported = errors.New("capture mode unsupported on this kernel")

// ModePreference picks a Capturer. If preferred is "tcbpf" or "afpacket" it is
// honored when supported; "auto" picks TC-BPF when the kernel has the
// required features, AF_PACKET otherwise.
func Pick(preferred string) (string, error) {
	switch preferred {
	case "tcbpf":
		if err := probeTCBPF(); err != nil {
			return "", fmt.Errorf("%w: tcbpf: %w", ErrUnsupported, err)
		}
		return "tcbpf", nil
	case "afpacket":
		return "afpacket", nil
	case "", "auto":
		if err := probeTCBPF(); err != nil {
			return "afpacket", nil
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
