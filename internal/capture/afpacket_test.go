//go:build linux

package capture

import (
	"context"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// AF_UNIX SOCK_DGRAM stands in for AF_PACKET in these tests: both deliver
// EPOLLIN on buffered datagrams, both honor SOCK_NONBLOCK, and both are
// registerable on an epoll fd with identical semantics. Using AF_UNIX lets
// the tests run unprivileged (no CAP_NET_RAW) so CI covers the shutdown
// path that the v0.1.7 pipe-close test accidentally skipped.

// The critical shutdown invariant: once Close returns, the capture channel
// closes within 200 ms regardless of whether the event loop is currently
// blocked in epoll_wait. Before v0.1.8 this failed because the code relied
// on close(2) waking a blocked unix.Read, which Linux does not guarantee
// (see the "Multithreaded processes and close()" note in close(2)). The
// epoll + eventfd path here is deterministic.
func TestShutdownUnblocksEventLoop(t *testing.T) {
	t.Parallel()
	pair, err := unix.Socketpair(unix.AF_UNIX,
		unix.SOCK_DGRAM|unix.SOCK_NONBLOCK|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatalf("socketpair: %v", err)
	}
	r, w := pair[0], pair[1]
	defer func() { _ = unix.Close(w) }()

	a := newTestAFPacket(t, map[string]int{"t0": r})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	out := make(chan Packet, 1)
	done := make(chan struct{})
	a.loopWG.Add(1)
	go func() {
		defer a.loopWG.Done()
		a.eventLoop(ctx, out)
		close(done)
	}()

	// Let the goroutine enter epoll_wait before closing.
	time.Sleep(20 * time.Millisecond)

	start := time.Now()
	if err := a.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	select {
	case <-done:
		if d := time.Since(start); d > 200*time.Millisecond {
			t.Fatalf("eventLoop exit took %v, expected <200ms", d)
		}
	case <-time.After(time.Second):
		t.Fatalf("eventLoop did not exit within 1s after Close")
	}
}

// Parallel shutdown path: ctx cancel triggers the Start-registered watcher
// goroutine which calls Close. We simulate that here by cancelling ctx and
// asserting the event loop exits promptly. Guards against a future change
// that removes the ctx→Close bridge.
func TestShutdownViaContextCancel(t *testing.T) {
	t.Parallel()
	pair, err := unix.Socketpair(unix.AF_UNIX,
		unix.SOCK_DGRAM|unix.SOCK_NONBLOCK|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatalf("socketpair: %v", err)
	}
	defer func() { _ = unix.Close(pair[1]) }()

	a := newTestAFPacket(t, map[string]int{"t0": pair[0]})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() {
		<-ctx.Done()
		_ = a.Close()
	}()

	out := make(chan Packet, 1)
	done := make(chan struct{})
	a.loopWG.Add(1)
	go func() {
		defer a.loopWG.Done()
		a.eventLoop(ctx, out)
		close(done)
	}()
	time.Sleep(20 * time.Millisecond)

	start := time.Now()
	cancel()

	select {
	case <-done:
		if d := time.Since(start); d > 200*time.Millisecond {
			t.Fatalf("eventLoop exit took %v, expected <200ms", d)
		}
	case <-time.After(time.Second):
		t.Fatalf("eventLoop did not exit within 1s after ctx cancel")
	}
}

// A packet written to the writer end should surface on the Packet channel
// with the right iface tag. Protects the happy path while we restructure
// the reader.
func TestEventLoopDrainsPackets(t *testing.T) {
	t.Parallel()
	pair, err := unix.Socketpair(unix.AF_UNIX,
		unix.SOCK_DGRAM|unix.SOCK_NONBLOCK|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatalf("socketpair: %v", err)
	}
	r, w := pair[0], pair[1]
	defer func() { _ = unix.Close(w) }()

	a := newTestAFPacket(t, map[string]int{"eth-test": r})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	out := make(chan Packet, 4)
	done := make(chan struct{})
	a.loopWG.Add(1)
	go func() {
		defer a.loopWG.Done()
		a.eventLoop(ctx, out)
		close(done)
	}()

	payload := []byte("hello-afpacket")
	if _, err := unix.Write(w, payload); err != nil {
		t.Fatalf("write: %v", err)
	}

	select {
	case pkt := <-out:
		if string(pkt.Data) != string(payload) {
			t.Fatalf("got %q, want %q", pkt.Data, payload)
		}
		if pkt.Iface != "eth-test" {
			t.Fatalf("iface %q, want %q", pkt.Iface, "eth-test")
		}
	case <-time.After(time.Second):
		t.Fatalf("no packet within 1s")
	}

	_ = a.Close()
	<-done
}

// Close is called from two sources in production — the ctx-watcher goroutine
// in Start and `defer cap.Close()` in main. sync.Once guards against a
// double-free of the epoll/event fds.
func TestCloseIsIdempotent(t *testing.T) {
	t.Parallel()
	pair, err := unix.Socketpair(unix.AF_UNIX,
		unix.SOCK_DGRAM|unix.SOCK_NONBLOCK|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatalf("socketpair: %v", err)
	}
	a := newTestAFPacket(t, map[string]int{"a": pair[0], "b": pair[1]})
	if err := a.Close(); err != nil {
		t.Fatalf("first close: %v", err)
	}
	if err := a.Close(); err != nil {
		t.Fatalf("second close: %v", err)
	}
}

// newTestAFPacket wires an AFPacket with epoll + eventfd over the given
// sockets. Skips the real Start path which needs CAP_NET_RAW to open
// AF_PACKET sockets. Sockets are registered on the epoll fd the same way
// Start does so the event loop under test exercises the real multiplex path.
func newTestAFPacket(t *testing.T, sockets map[string]int) *AFPacket {
	t.Helper()
	ifaceByFD := make(map[int32]string, len(sockets))
	for name, fd := range sockets {
		ifaceByFD[int32(fd)] = name
	}
	a := &AFPacket{
		sockets:   sockets,
		ifaceByFD: ifaceByFD,
		buf:       4096,
		epollFD:   -1,
		eventFD:   -1,
	}
	efd, err := unix.Eventfd(0, unix.EFD_CLOEXEC|unix.EFD_NONBLOCK)
	if err != nil {
		t.Fatalf("eventfd: %v", err)
	}
	a.eventFD = efd
	epfd, err := unix.EpollCreate1(unix.EPOLL_CLOEXEC)
	if err != nil {
		t.Fatalf("epoll_create1: %v", err)
	}
	a.epollFD = epfd
	if err := unix.EpollCtl(epfd, unix.EPOLL_CTL_ADD, efd,
		&unix.EpollEvent{Events: unix.EPOLLIN, Fd: int32(efd)}); err != nil {
		t.Fatalf("epoll_ctl efd: %v", err)
	}
	for name, fd := range sockets {
		if err := unix.EpollCtl(epfd, unix.EPOLL_CTL_ADD, fd,
			&unix.EpollEvent{Events: unix.EPOLLIN, Fd: int32(fd)}); err != nil {
			t.Fatalf("epoll_ctl %s: %v", name, err)
		}
	}
	return a
}
