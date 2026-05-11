//go:build linux

package capture

import (
	"context"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// readLoop must exit cleanly when unix.Read returns EBADF — that is the
// codepath the Start() ctx-watcher relies on to unblock a quiet-node
// shutdown (see afpacket.go:85-91 and the v0.1.7 plan's traced deadlock).
//
// Two things we can't test in a userspace unit test:
//  1. AF_PACKET sockets specifically (no CAP_NET_RAW in CI).
//  2. The kernel wake-on-close semantic that turns a *blocked* Read into
//     EBADF on AF_PACKET. Pipe fds don't share that semantic — closing
//     a pipe's read-end while another goroutine is blocked reading from
//     it will NOT wake the reader on Linux.
//
// What we can test is the Go-side invariant: given a Read that returns
// EBADF, readLoop returns. Close the fd first, start readLoop, the very
// first unix.Read call gets EBADF and the EBADF branch exits the loop.
func TestReadLoopExitsOnEBADF(t *testing.T) {
	fds := make([]int, 2)
	if err := unix.Pipe(fds); err != nil {
		t.Fatalf("pipe: %v", err)
	}
	r, w := fds[0], fds[1]
	_ = unix.Close(w)
	_ = unix.Close(r) // r is now invalid — next unix.Read returns EBADF

	a := &AFPacket{buf: 4096, sockets: map[string]int{}}
	out := make(chan Packet, 1)
	done := make(chan struct{})
	go func() {
		a.readLoop(context.Background(), "test", r, out)
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatalf("readLoop did not exit within 1s on closed fd")
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
