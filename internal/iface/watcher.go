//go:build linux

package iface

import (
	"context"
	"log/slog"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

// Watch subscribes to kernel RTM_NEWLINK / RTM_DELLINK events and calls onAdd
// or onRemove for every pod-veth interface that appears or disappears.
//
// Before entering the event loop Watch calls ListPodVeths and fires onAdd for
// each interface already present, closing the race window between the initial
// snapshot in main and the subscription start.
//
// Watch blocks until ctx is cancelled, then returns nil.
func Watch(ctx context.Context, onAdd func(string), onRemove func(string)) error {
	ch := make(chan netlink.LinkUpdate, 32)
	done := make(chan struct{})
	go func() {
		<-ctx.Done()
		close(done)
	}()

	if err := netlink.LinkSubscribeWithOptions(ch, done, netlink.LinkSubscribeOptions{
		ErrorCallback: func(err error) {
			slog.Warn("iface watcher netlink error", "err", err)
		},
	}); err != nil {
		return err
	}

	// Snapshot existing pod-veths before entering the event loop to cover
	// interfaces that appeared between ListPodVeths() at startup and now.
	if existing, err := ListPodVeths(); err == nil {
		for _, name := range existing {
			onAdd(name)
		}
	}

	for {
		select {
		case <-ctx.Done():
			return nil
		case upd, ok := <-ch:
			if !ok {
				return nil
			}
			name := upd.Link.Attrs().Name
			if !IsPodVeth(name) {
				continue
			}
			switch upd.Header.Type {
			case unix.RTM_NEWLINK:
				// RTM_NEWLINK fires on create AND on attribute changes (e.g. link
				// coming up). Only attach once the interface is actually UP.
				if upd.IfInfomsg.Flags&unix.IFF_UP != 0 {
					onAdd(name)
				}
			case unix.RTM_DELLINK:
				onRemove(name)
			}
		}
	}
}
