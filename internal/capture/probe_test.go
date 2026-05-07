//go:build linux

package capture

import (
	"strings"
	"testing"
)

// Pick's behavior when "tcbpf" is requested and "auto" is requested both
// depend on probeTCBPF, which touches the kernel. We can't force probe
// outcomes in a unit test, so we only assert the paths that don't require
// probing: explicit "afpacket", unknown modes, and empty/"" defaulting to
// auto.
func TestPickExplicitAFPacket(t *testing.T) {
	got, err := Pick("afpacket")
	if err != nil {
		t.Fatalf("Pick(afpacket): %v", err)
	}
	if got != "afpacket" {
		t.Errorf("Pick(afpacket) = %q, want %q", got, "afpacket")
	}
}

func TestPickUnknownMode(t *testing.T) {
	_, err := Pick("xdp")
	if err == nil {
		t.Fatal("Pick(xdp) returned nil error, want unknown-mode error")
	}
	if !strings.Contains(err.Error(), "unknown capture mode") {
		t.Errorf("error = %v, want containing %q", err, "unknown capture mode")
	}
}

// "auto" and "" both route through probeTCBPF, so the returned mode depends
// on the test host's kernel. What we can guarantee is that Pick never returns
// an error for these cases (falls back to afpacket) and always returns one of
// the two valid mode strings.
func TestPickAutoAndEmpty(t *testing.T) {
	for _, pref := range []string{"auto", ""} {
		got, err := Pick(pref)
		if err != nil {
			t.Errorf("Pick(%q): unexpected error %v", pref, err)
			continue
		}
		if got != "tcbpf" && got != "afpacket" {
			t.Errorf("Pick(%q) = %q, want tcbpf or afpacket", pref, got)
		}
	}
}
