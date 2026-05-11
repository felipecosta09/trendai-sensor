//go:build !linux

package iface

import "context"

// Watch is a no-op on non-Linux platforms. The sensor binary is always built
// for Linux; this stub exists so IDE tooling and go vet work on macOS.
func Watch(_ context.Context, _ func(string), _ func(string)) error {
	return nil
}
