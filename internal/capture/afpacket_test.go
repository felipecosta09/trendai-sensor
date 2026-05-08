//go:build linux

package capture

import (
	"context"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// readLoop blocks in unix.Read with no deadline; the only way a ctx-watcher
// goroutine can unblock it on a quiet node is to close the fd and have the
// EBADF branch exit the loop. If this test hangs we regressed the fix for
// the v0.1.6 / v0.1.7 shutdown deadlock.
//
// A pipe fd stands in for an AF_PACKET socket here — unit tests don't have
// CAP_NET_RAW — but the blocking + EBADF-on-close semantics are the same.
func TestReadLoopExitsOnFDClose(t *testing.T) {
	fds := make([]int, 2)
	if err := unix.Pipe(fds); err != nil {
		t.Fatalf("pipe: %v", err)
	}
	r, w := fds[0], fds[1]
	defer unix.Close(w)

	a := &AFPacket{buf: 4096, sockets: map[string]int{"test": r}}
	out := make(chan Packet, 1)
	done := make(chan struct{})
	go func() {
		a.readLoop(context.Background(), "test", r, out)
		close(done)
	}()

	// Give readLoop a beat to enter unix.Read before we close the fd.
	time.Sleep(20 * time.Millisecond)

	if err := unix.Close(r); err != nil {
		t.Fatalf("close fd: %v", err)
	}

	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatalf("readLoop did not exit within 1s after fd close")
	}
}

// Close must be idempotent (sync.Once) so the ctx-watcher goroutine and the
// deferred cap.Close() in main can't double-free.
func TestCloseIsIdempotent(t *testing.T) {
	fds := make([]int, 2)
	if err := unix.Pipe(fds); err != nil {
		t.Fatalf("pipe: %v", err)
	}
	a := &AFPacket{sockets: map[string]int{"a": fds[0], "b": fds[1]}}
	if err := a.Close(); err != nil {
		t.Fatalf("first close: %v", err)
	}
	if err := a.Close(); err != nil {
		t.Fatalf("second close: %v", err)
	}
}
