package ports

import (
	"net"
	"os"
	"testing"
	"time"

	"github.com/vishvananda/netlink"

	"github.com/HuJK/gvisor-vswitch/internal/switchcore"
)

func TestTapPortLifecycle(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires root (CAP_NET_ADMIN)")
	}
	sw, _ := newSwitchWithCapture(t)

	p, err := NewTap(sw, TapConfig{ID: "tap1", TapName: "gvswtest0"})
	if err != nil {
		t.Fatalf("NewTap: %v", err)
	}
	if err := sw.AddPort(p, switchcore.PortAttrs{VLAN: switchcore.VLANTrunk}); err != nil {
		t.Fatal(err)
	}

	if _, err := netlink.LinkByName("gvswtest0"); err != nil {
		t.Fatalf("tap device missing: %v", err)
	}
	if st := p.Status(); !st.Online {
		t.Error("tap port offline")
	}

	// Egress path must accept frames.
	if ok := p.Send(switchcore.Meta{}, testFrame(1)); !ok {
		t.Error("Send failed")
	}

	sw.RemovePort("tap1")
	deadline := time.Now().Add(2 * time.Second)
	for {
		if _, err := netlink.LinkByName("gvswtest0"); err != nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("tap device still present after port removal")
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func TestTapBrRequiresBridge(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires root (CAP_NET_ADMIN)")
	}
	sw, _ := newSwitchWithCapture(t)
	if _, err := NewTap(sw, TapConfig{ID: "tap2", TapName: "gvswtest1", AddToBr: true, Bridge: "no-such-br0"}); err == nil {
		t.Fatal("tapbr with missing bridge succeeded")
	}
	if _, err := netlink.LinkByName("gvswtest1"); err == nil {
		netlink.LinkDel(&netlink.GenericLink{LinkAttrs: netlink.LinkAttrs{Name: "gvswtest1"}})
		t.Fatal("tap leaked after failed tapbr setup")
	}
}

func TestVsockStreamLoopback(t *testing.T) {
	// vsock loopback (CID 1) needs the vsock_loopback module.
	ln, err := listenVsockStream(":10240")
	if err != nil {
		t.Skipf("vsock unavailable: %v", err)
	}
	defer ln.Close()

	done := make(chan struct{})
	go func() {
		defer close(done)
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		buf := make([]byte, 8)
		n, _ := c.Read(buf)
		c.Write(buf[:n])
	}()

	conn, err := dialVsockStream("", "1:10240")
	if err != nil {
		t.Skipf("vsock loopback dial unavailable: %v", err)
	}
	defer conn.Close()
	conn.Write([]byte("ping"))
	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 8)
	n, err := conn.Read(buf)
	if err != nil || string(buf[:n]) != "ping" {
		t.Fatalf("loopback echo: %q err=%v", buf[:n], err)
	}
	<-done

	// peerString for a vsock conn must be cid:port.
	if got := peerString(conn); got == "" {
		t.Error("empty peerString for vsock conn")
	}
}

var _ = net.IPv4zero
