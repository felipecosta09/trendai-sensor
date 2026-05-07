//go:build !linux

package capture

import (
	"context"
	"errors"

	filterpkg "github.com/trendai/sensor/internal/filter"
)

// Non-Linux builds exist only so IDE and go vet work on macOS dev machines.
// The binary itself is always built for Linux (see Makefile).

func Pick(_ string) (string, error) {
	return "", errors.New("capture is only supported on linux")
}

type stub struct{ mode string }

func NewTCBPF() (Capturer, error)           { return nil, errors.New("linux only") }
func NewAFPacket(_ filterpkg.Spec) Capturer { return &stub{mode: "afpacket-stub"} }
func (s *stub) Start(context.Context, []string) (<-chan Packet, error) {
	return nil, errors.New("linux only")
}
func (s *stub) Stats() Stats { return Stats{} }
func (s *stub) Close() error { return nil }
func (s *stub) Mode() string { return s.mode }
