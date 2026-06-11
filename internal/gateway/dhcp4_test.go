package gateway

import (
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/insomniacslk/dhcp/dhcpv4"

	"github.com/HuJK/gvisor-vswitch/internal/switchcore"
)

// capPort records frames the switch sends it.
type capPort struct {
	id   string
	mu   sync.Mutex
	fr   [][]byte
	seen int // frames already consumed by waitDHCP
}

func (p *capPort) ID() string { return p.id }
func (p *capPort) Send(_ switchcore.Meta, frame []byte) bool {
	p.mu.Lock()
	p.fr = append(p.fr, frame)
	p.mu.Unlock()
	return true
}
func (p *capPort) Close() error { return nil }

// waitDHCP waits for a DHCPv4 reply frame and decodes it.
func (p *capPort) waitDHCP(t *testing.T) *dhcpv4.DHCPv4 {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for {
		p.mu.Lock()
		frames := p.fr[p.seen:]
		p.seen = len(p.fr)
		p.mu.Unlock()
		for _, f := range frames {
			pkt, ok := parseIngress(f)
			if !ok || !pkt.isUDP4 || pkt.dstPort != dhcp4ClientPort {
				continue
			}
			d, err := dhcpv4.FromBytes(pkt.payload)
			if err != nil {
				t.Fatalf("bad DHCP reply: %v", err)
			}
			return d
		}
		if time.Now().After(deadline) {
			t.Fatal("no DHCP reply")
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func newDHCPTestGateway(t *testing.T) (*switchcore.Switch, *Gateway, *capPort) {
	t.Helper()
	sw := switchcore.New()
	t.Cleanup(sw.Close)

	gw, err := New(sw, Config{
		PortID: "gw",
		MAC:    net.HardwareAddr{0x52, 0x54, 0, 0, 0, 0xfe},
		IPv4:   &V4Config{Address: net.IPv4(10, 0, 99, 2).To4(), PrefixLen: 24},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := sw.AddPort(gw, switchcore.PortAttrs{VLAN: 100}); err != nil {
		t.Fatal(err)
	}

	vm := &capPort{id: "vm1"}
	if err := sw.AddPort(vm, switchcore.PortAttrs{VLAN: 100}); err != nil {
		t.Fatal(err)
	}

	err = gw.DHCP4().SetConfig(DHCP4Config{
		Enabled:   true,
		PoolStart: netip.MustParseAddr("10.0.99.10"),
		PoolEnd:   netip.MustParseAddr("10.0.99.20"),
		LeaseTime: time.Hour,
	})
	if err != nil {
		t.Fatal(err)
	}
	return sw, gw, vm
}

func discoverFrame(t *testing.T, mac net.HardwareAddr, mods ...dhcpv4.Modifier) []byte {
	t.Helper()
	mods = append([]dhcpv4.Modifier{
		dhcpv4.WithHwAddr(mac),
		dhcpv4.WithMessageType(dhcpv4.MessageTypeDiscover),
		dhcpv4.WithBroadcast(true),
	}, mods...)
	req, err := dhcpv4.New(mods...)
	if err != nil {
		t.Fatal(err)
	}
	return craftUDP4(mac, broadcastMAC, net.IPv4zero, broadcastIP4,
		dhcp4ClientPort, dhcp4ServerPort, req.ToBytes())
}

func requestFrame(t *testing.T, mac net.HardwareAddr, ip net.IP) []byte {
	t.Helper()
	req, err := dhcpv4.New(
		dhcpv4.WithHwAddr(mac),
		dhcpv4.WithMessageType(dhcpv4.MessageTypeRequest),
		dhcpv4.WithBroadcast(true),
		dhcpv4.WithOption(dhcpv4.OptRequestedIPAddress(ip)),
		dhcpv4.WithOption(dhcpv4.OptServerIdentifier(net.IPv4(10, 0, 99, 2))),
	)
	if err != nil {
		t.Fatal(err)
	}
	return craftUDP4(mac, broadcastMAC, net.IPv4zero, broadcastIP4,
		dhcp4ClientPort, dhcp4ServerPort, req.ToBytes())
}

func TestDHCP4DiscoverOfferRequestAck(t *testing.T) {
	sw, gw, vm := newDHCPTestGateway(t)
	mac := net.HardwareAddr{0x02, 0, 0, 0, 0, 0x11}

	sw.Deliver("vm1", discoverFrame(t, mac))
	offer := vm.waitDHCP(t)
	if offer.MessageType() != dhcpv4.MessageTypeOffer {
		t.Fatalf("got %s, want OFFER", offer.MessageType())
	}
	ip := offer.YourIPAddr
	got := netip.MustParseAddr(ip.String())
	if got.Less(netip.MustParseAddr("10.0.99.10")) || netip.MustParseAddr("10.0.99.20").Less(got) {
		t.Fatalf("offered %s outside pool", ip)
	}
	if mask := offer.Options.Get(dhcpv4.OptionSubnetMask); len(mask) != 4 || mask[0] != 255 || mask[2] != 255 {
		t.Errorf("subnet mask = %v", mask)
	}
	if r := offer.Options.Get(dhcpv4.OptionRouter); len(r) != 4 || r[3] != 2 {
		t.Errorf("router = %v", r)
	}

	sw.Deliver("vm1", requestFrame(t, mac, ip))
	ack := vm.waitDHCP(t)
	if ack.MessageType() != dhcpv4.MessageTypeAck {
		t.Fatalf("got %s, want ACK", ack.MessageType())
	}
	if !ack.YourIPAddr.Equal(ip) {
		t.Fatalf("ACK ip %s != offered %s", ack.YourIPAddr, ip)
	}

	leases := gw.DHCP4().Leases()
	if len(leases) != 1 || leases[0].PortID != "vm1" || leases[0].MAC != mac.String() {
		t.Fatalf("leases = %+v", leases)
	}

	// Same client asks again: same address.
	sw.Deliver("vm1", discoverFrame(t, mac))
	offer2 := vm.waitDHCP(t)
	if !offer2.YourIPAddr.Equal(ip) {
		t.Errorf("rediscover gave %s, want %s", offer2.YourIPAddr, ip)
	}
}

func TestDHCP4RequestWrongIPNak(t *testing.T) {
	sw, _, vm := newDHCPTestGateway(t)
	mac := net.HardwareAddr{0x02, 0, 0, 0, 0, 0x12}

	// REQUEST for the gateway's own IP -> NAK.
	sw.Deliver("vm1", requestFrame(t, mac, net.IPv4(10, 0, 99, 2)))
	nak := vm.waitDHCP(t)
	if nak.MessageType() != dhcpv4.MessageTypeNak {
		t.Fatalf("got %s, want NAK", nak.MessageType())
	}
}

func TestDHCP4StaticBindingPriority(t *testing.T) {
	sw, gw, vm := newDHCPTestGateway(t)
	mac := net.HardwareAddr{0x02, 0, 0, 0, 0, 0x13}
	macStr := mac.String()
	port := "vm1"

	// MAC-only binding (1 condition) and MAC+port binding (2 conditions):
	// the more specific one must win.
	if err := gw.DHCP4().PutStatic(StaticBinding{
		ID: "weak", MAC: &macStr, IP: netip.MustParseAddr("10.0.99.50"),
	}); err != nil {
		t.Fatal(err)
	}
	if err := gw.DHCP4().PutStatic(StaticBinding{
		ID: "strong", MAC: &macStr, PortID: &port, IP: netip.MustParseAddr("10.0.99.60"),
	}); err != nil {
		t.Fatal(err)
	}

	sw.Deliver("vm1", discoverFrame(t, mac))
	offer := vm.waitDHCP(t)
	if got := offer.YourIPAddr.String(); got != "10.0.99.60" {
		t.Fatalf("offered %s, want 10.0.99.60 (most-specific binding)", got)
	}

	// Static lease is marked static.
	sw.Deliver("vm1", requestFrame(t, mac, offer.YourIPAddr))
	if ack := vm.waitDHCP(t); ack.MessageType() != dhcpv4.MessageTypeAck {
		t.Fatalf("want ACK, got %s", ack.MessageType())
	}
	leases := gw.DHCP4().Leases()
	if len(leases) != 1 || !leases[0].Static {
		t.Fatalf("leases = %+v, want one static", leases)
	}
}

func TestDHCP4PortDownReleasesLease(t *testing.T) {
	sw, gw, vm := newDHCPTestGateway(t)
	mac := net.HardwareAddr{0x02, 0, 0, 0, 0, 0x14}

	sw.Deliver("vm1", discoverFrame(t, mac))
	offer := vm.waitDHCP(t)
	sw.Deliver("vm1", requestFrame(t, mac, offer.YourIPAddr))
	vm.waitDHCP(t)
	if len(gw.DHCP4().Leases()) != 1 {
		t.Fatal("no lease recorded")
	}

	gw.PortDown("vm1")
	if got := len(gw.DHCP4().Leases()); got != 0 {
		t.Fatalf("leases after port down = %d, want 0", got)
	}
}

func TestDHCP4ForceRelease(t *testing.T) {
	sw, gw, vm := newDHCPTestGateway(t)
	mac := net.HardwareAddr{0x02, 0, 0, 0, 0, 0x15}

	sw.Deliver("vm1", discoverFrame(t, mac))
	offer := vm.waitDHCP(t)
	ip := netip.MustParseAddr(offer.YourIPAddr.String())

	if err := gw.DHCP4().ReleaseLease(ip); err != nil {
		t.Fatal(err)
	}
	if err := gw.DHCP4().ReleaseLease(ip); err == nil {
		t.Error("double release succeeded")
	}
}

func TestMatchBindingOrderTieBreak(t *testing.T) {
	port := "p1"
	b1 := &StaticBinding{ID: "low", Order: 1, PortID: &port, IP: netip.MustParseAddr("10.0.0.1")}
	b2 := &StaticBinding{ID: "high", Order: 9, PortID: &port, IP: netip.MustParseAddr("10.0.0.2")}

	got := matchBinding([]*StaticBinding{b1, b2}, "p1", "02:00:00:00:00:01", "")
	if got == nil || got.ID != "high" {
		t.Fatalf("matchBinding = %+v, want high-order binding", got)
	}

	// A binding whose non-wildcard condition mismatches is out, even if
	// other conditions match.
	mac := "02:00:00:00:00:01"
	other := "02:00:00:00:00:99"
	b3 := &StaticBinding{ID: "mismatch", Order: 99, PortID: &port, MAC: &other, IP: netip.MustParseAddr("10.0.0.3")}
	got = matchBinding([]*StaticBinding{b1, b3}, "p1", mac, "")
	if got == nil || got.ID != "low" {
		t.Fatalf("matchBinding = %+v, want low (mismatch excluded)", got)
	}

	// No bindings match -> nil.
	if got := matchBinding([]*StaticBinding{b3}, "p2", mac, ""); got != nil {
		t.Fatalf("matchBinding = %+v, want nil", got)
	}
}
