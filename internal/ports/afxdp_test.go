//go:build linux && (amd64 || arm64)

package ports

import (
	"bytes"
	"os"
	"testing"
	"time"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"

	"github.com/HuJK/gvisor-vswitch/internal/switchcore"
)

// rawSocket opens an AF_PACKET socket bound to the interface, for talking
// to the af_xdp port from the "outside world" end of a veth pair.
func rawSocket(t *testing.T, ifindex int) int {
	t.Helper()
	proto := int(htons(unix.ETH_P_ALL))
	fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW|unix.SOCK_CLOEXEC, proto)
	if err != nil {
		t.Fatalf("AF_PACKET socket: %v", err)
	}
	t.Cleanup(func() { unix.Close(fd) })
	if err := unix.Bind(fd, &unix.SockaddrLinklayer{Protocol: htons(unix.ETH_P_ALL), Ifindex: ifindex}); err != nil {
		t.Fatalf("bind AF_PACKET: %v", err)
	}
	tv := unix.Timeval{Sec: 2}
	unix.SetsockoptTimeval(fd, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &tv)
	return fd
}

func htons(v uint16) uint16 { return v<<8 | v>>8 }

func TestAFXDPPortOverVeth(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires root")
	}

	// veth pair: the af_xdp port takes over gvswxa; the test talks on
	// gvswxb.
	veth := &netlink.Veth{
		LinkAttrs: netlink.LinkAttrs{Name: "gvswxa"},
		PeerName:  "gvswxb",
	}
	netlink.LinkDel(veth) // clean leftovers from crashed runs
	if err := netlink.LinkAdd(veth); err != nil {
		t.Fatalf("create veth: %v", err)
	}
	t.Cleanup(func() { netlink.LinkDel(veth) })
	peer, err := netlink.LinkByName("gvswxb")
	if err != nil {
		t.Fatal(err)
	}
	if err := netlink.LinkSetUp(veth); err != nil {
		t.Fatal(err)
	}
	if err := netlink.LinkSetUp(peer); err != nil {
		t.Fatal(err)
	}

	sw, cap := newSwitchWithCapture(t)
	p, err := NewAFXDP(sw, AFXDPConfig{ID: "xdp1", Interface: "gvswxa"})
	if err != nil {
		t.Skipf("af_xdp unavailable: %v", err)
	}
	if err := sw.AddPort(p, switchcore.PortAttrs{VLAN: switchcore.VLANTrunk}); err != nil {
		t.Fatal(err)
	}
	if st := p.Status(); !st.Online || st.Peer != "gvswxa" {
		t.Errorf("status = %+v", st)
	}

	raw := rawSocket(t, peer.Attrs().Index)

	// Ingress: a frame written on gvswxb must arrive at the capture port
	// through the XDP redirect. The kernel may emit its own frames (IPv6
	// RS/MLD), so look for our marker payload.
	want := testFrame(0x5a)
	deadline := time.Now().Add(3 * time.Second)
	got := false
	for !got && time.Now().Before(deadline) {
		if _, err := unix.Write(raw, want); err != nil {
			t.Fatalf("raw write: %v", err)
		}
		time.Sleep(50 * time.Millisecond)
		cap.mu.Lock()
		for _, f := range cap.fr {
			if len(f) >= 15 && bytes.Equal(f[:15], want[:15]) {
				got = true
			}
		}
		cap.mu.Unlock()
	}
	if !got {
		t.Fatal("ingress frame never reached the switch via af_xdp")
	}

	// Egress: a frame delivered from the capture port must appear on
	// gvswxb.
	out := testFrame(0xa5)
	sw.Deliver("cap", out)
	buf := make([]byte, 4096)
	deadline = time.Now().Add(3 * time.Second)
	for {
		n, err := unix.Read(raw, buf)
		if err != nil {
			if time.Now().After(deadline) {
				t.Fatalf("egress frame never seen on veth peer: %v", err)
			}
			sw.Deliver("cap", out) // retry; first TX may race link readiness
			continue
		}
		if n >= 15 && bytes.Equal(buf[:15], out[:15]) {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("egress frame never seen on veth peer")
		}
	}

	// Stats must reflect traffic.
	if st, _ := sw.PortStats("xdp1"); st.RxFrames == 0 || st.TxFrames == 0 {
		t.Errorf("stats = %+v, want rx and tx counted", st)
	}

	// Close: XDP program detached, promisc restored.
	sw.RemovePort("xdp1")
	if st := p.Status(); st.Online {
		t.Error("port still online after removal")
	}
	lnk, err := netlink.LinkByName("gvswxa")
	if err == nil && lnk.Attrs().Xdp != nil && lnk.Attrs().Xdp.Attached {
		t.Error("XDP program still attached after close")
	}
}

func TestAFXDPLinkGoneTakesPortOffline(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires root")
	}

	veth := &netlink.Veth{
		LinkAttrs: netlink.LinkAttrs{Name: "gvswxc"},
		PeerName:  "gvswxd",
	}
	netlink.LinkDel(veth)
	if err := netlink.LinkAdd(veth); err != nil {
		t.Fatalf("create veth: %v", err)
	}
	t.Cleanup(func() { netlink.LinkDel(veth) })
	netlink.LinkSetUp(veth)

	sw, _ := newSwitchWithCapture(t)
	downCh := make(chan string, 4)
	sw.OnPortDown(func(id string) { downCh <- id })

	p, err := NewAFXDP(sw, AFXDPConfig{ID: "xdp2", Interface: "gvswxc"})
	if err != nil {
		t.Skipf("af_xdp unavailable: %v", err)
	}
	if err := sw.AddPort(p, switchcore.PortAttrs{VLAN: switchcore.VLANTrunk}); err != nil {
		t.Fatal(err)
	}

	// Simulate qemu shutdown / NIC hotplug-removal.
	start := time.Now()
	if err := netlink.LinkDel(veth); err != nil {
		t.Fatal(err)
	}

	deadline := time.Now().Add(5 * time.Second)
	for p.Status().Online {
		if time.Now().After(deadline) {
			t.Fatal("port still online after interface deletion")
		}
		time.Sleep(10 * time.Millisecond)
	}
	// Event-driven (netlink RTM_DELLINK) detection must be fast; the
	// 2s periodic check is only the no-subscription fallback.
	if elapsed := time.Since(start); elapsed > 1500*time.Millisecond {
		t.Errorf("detection took %v, want event-driven (<1.5s)", elapsed)
	}
	select {
	case id := <-downCh:
		if id != "xdp2" {
			t.Errorf("port-down for %q, want xdp2", id)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("no port-down event after interface deletion")
	}
}
