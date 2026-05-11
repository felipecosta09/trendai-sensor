//go:build linux

package iface

import (
	"context"
	"testing"
	"time"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

func TestWatcherExitsOnCtxCancel(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // pre-cancel so Watch returns as soon as it starts the event loop

	done := make(chan error, 1)
	go func() {
		done <- Watch(ctx, func(string) {}, func(string) {})
	}()

	select {
	case err := <-done:
		if err != nil {
			// netlink subscription may fail without CAP_NET_ADMIN — treat as pass
			t.Logf("Watch returned (err=%v)", err)
		}
	case <-time.After(500 * time.Millisecond):
		t.Error("Watch did not exit within 500ms after ctx was pre-cancelled")
	}
}

func TestApplyUpdate(t *testing.T) {
	cases := []struct {
		name       string
		msgType    uint16
		ifname     string
		flags      uint32
		wantAdd    string
		wantRemove string
	}{
		{
			name: "newlink_up_pod_veth",
			msgType: unix.RTM_NEWLINK, ifname: "eni12345", flags: unix.IFF_UP,
			wantAdd: "eni12345",
		},
		{
			name: "newlink_no_up_skipped",
			msgType: unix.RTM_NEWLINK, ifname: "eni12345", flags: 0,
		},
		{
			name: "dellink_pod_veth",
			msgType: unix.RTM_DELLINK, ifname: "veth1abc", flags: 0,
			wantRemove: "veth1abc",
		},
		{
			name: "non_pod_veth_ignored",
			msgType: unix.RTM_NEWLINK, ifname: "eth0", flags: unix.IFF_UP,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var added, removed string
			upd := netlink.LinkUpdate{
				Header:    unix.NlMsghdr{Type: tc.msgType},
				IfInfomsg: unix.IfInfomsg{Flags: tc.flags},
				Link:      &netlink.Dummy{LinkAttrs: netlink.LinkAttrs{Name: tc.ifname}},
			}
			applyUpdate(upd, func(n string) { added = n }, func(n string) { removed = n })
			if added != tc.wantAdd {
				t.Errorf("added = %q, want %q", added, tc.wantAdd)
			}
			if removed != tc.wantRemove {
				t.Errorf("removed = %q, want %q", removed, tc.wantRemove)
			}
		})
	}
}
