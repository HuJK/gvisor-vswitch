package gateway

import (
	"encoding/binary"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/insomniacslk/dhcp/dhcpv6"
	"gvisor.dev/gvisor/pkg/tcpip/header"

	"github.com/HuJK/gvisor-vswitch/internal/switchcore"
)

var allRoutersDHCP6 = net.ParseIP("ff02::1:2")

func newV6TestGateway(t *testing.T) (*switchcore.Switch, *Gateway, *capPort) {
	t.Helper()
	sw := switchcore.New()
	t.Cleanup(sw.Close)

	gw, err := New(sw, Config{
		PortID: "gw",
		MAC:    net.HardwareAddr{0x52, 0x54, 0, 0, 0, 0xfe},
		IPv6:   &V6Config{Address: net.ParseIP("fd99::2"), PrefixLen: 64},
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
	return sw, gw, vm
}

// waitFrame waits for a frame matching pred.
func (p *capPort) waitFrame(t *testing.T, what string, pred func(ingressPacket) bool) ingressPacket {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for {
		p.mu.Lock()
		frames := p.fr[p.seen:]
		p.seen = len(p.fr)
		p.mu.Unlock()
		for _, f := range frames {
			pkt, ok := parseIngress(f)
			if ok && pred(pkt) {
				return pkt
			}
		}
		if time.Now().After(deadline) {
			t.Fatalf("no %s frame", what)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func TestRouterAdvertisementOnSolicit(t *testing.T) {
	sw, gw, vm := newV6TestGateway(t)

	err := gw.RA().SetConfig(SLAACConfig{
		Enabled: true,
		Other:   true,
		Prefixes: []RAPrefix{{
			Prefix:     netip.MustParsePrefix("fd99::/64"),
			OnLink:     true,
			Autonomous: true,
		}},
	})
	if err != nil {
		t.Fatal(err)
	}

	// Periodic RA arrives even without solicitation.
	ra := vm.waitFrame(t, "periodic RA", func(p ingressPacket) bool {
		return p.isICMP6 && p.icmpTyp == uint8(header.ICMPv6RouterAdvert)
	})

	icmp := header.ICMPv6(ra.payload)
	body := icmp.MessageBody()
	if lifetime := binary.BigEndian.Uint16(body[2:4]); lifetime == 0 {
		t.Errorf("router lifetime = 0, want default")
	}
	if body[1]&(1<<6) == 0 {
		t.Errorf("O flag not set")
	}

	// Prefix option present with L+A flags and our prefix.
	opts := header.NDPOptions(body[header.NDPRAMinimumSize:])
	it, err := opts.Iter(true)
	if err != nil {
		t.Fatalf("bad NDP options: %v", err)
	}
	foundPrefix := false
	for {
		opt, done, err := it.Next()
		if err != nil || done {
			break
		}
		if pi, ok := opt.(header.NDPPrefixInformation); ok {
			foundPrefix = true
			if pi.PrefixLength() != 64 || !pi.OnLinkFlag() || !pi.AutonomousAddressConfigurationFlag() {
				t.Errorf("prefix info: len=%d L=%v A=%v", pi.PrefixLength(), pi.OnLinkFlag(), pi.AutonomousAddressConfigurationFlag())
			}
			if got := pi.Prefix().String(); got != "fd99::" {
				t.Errorf("prefix = %s, want fd99::", got)
			}
		}
	}
	if !foundPrefix {
		t.Fatal("no prefix information option in RA")
	}

	// Solicited RA: send an RS from the VM's link-local address.
	vmMAC := net.HardwareAddr{0x02, 0, 0, 0, 0, 0x21}
	vmLL := net.ParseIP("fe80::1234")
	rsBody := make([]byte, header.ICMPv6HeaderSize+4)
	header.ICMPv6(rsBody).SetType(header.ICMPv6RouterSolicit)
	rs := craftICMP6(vmMAC, allNodesMAC, vmLL, net.ParseIP("ff02::2"), rsBody, header.NDPHopLimit)
	sw.Deliver("vm1", rs)

	sol := vm.waitFrame(t, "solicited RA", func(p ingressPacket) bool {
		return p.isICMP6 && p.icmpTyp == uint8(header.ICMPv6RouterAdvert) && p.dstIP.Equal(vmLL)
	})
	if !sol.srcIP.Equal(gw.LinkLocal()) {
		t.Errorf("RA source %s, want gateway link-local %s", sol.srcIP, gw.LinkLocal())
	}
}

func solicitFrame(t *testing.T, mac net.HardwareAddr, ll net.IP) ([]byte, *dhcpv6.Message) {
	t.Helper()
	sol, err := dhcpv6.NewSolicit(mac)
	if err != nil {
		t.Fatal(err)
	}
	return craftUDP6(mac, net.HardwareAddr{0x33, 0x33, 0, 1, 0, 2}, ll, allRoutersDHCP6,
		dhcp6ClientPort, dhcp6ServerPort, sol.ToBytes()), sol
}

func TestDHCP6SolicitAdvertiseRequestReply(t *testing.T) {
	sw, gw, vm := newV6TestGateway(t)

	err := gw.DHCP6().SetConfig(DHCP6Config{
		Enabled:   true,
		PoolStart: netip.MustParseAddr("fd99::100"),
		PoolEnd:   netip.MustParseAddr("fd99::1ff"),
		LeaseTime: time.Hour,
	})
	if err != nil {
		t.Fatal(err)
	}

	mac := net.HardwareAddr{0x02, 0, 0, 0, 0, 0x31}
	ll := net.ParseIP("fe80::31")

	frame, sol := solicitFrame(t, mac, ll)
	sw.Deliver("vm1", frame)

	advPkt := vm.waitFrame(t, "ADVERTISE", func(p ingressPacket) bool {
		return p.isUDP6 && p.dstPort == dhcp6ClientPort
	})
	d, err := dhcpv6.FromBytes(advPkt.payload)
	if err != nil {
		t.Fatal(err)
	}
	adv := d.(*dhcpv6.Message)
	if adv.MessageType != dhcpv6.MessageTypeAdvertise {
		t.Fatalf("got %s, want ADVERTISE", adv.MessageType)
	}
	ia := adv.Options.OneIANA()
	if ia == nil {
		t.Fatal("no IA_NA in advertise")
	}
	addrs := ia.Options.Addresses()
	if len(addrs) != 1 {
		t.Fatalf("IA addresses = %v", addrs)
	}
	got := netip.MustParseAddr(addrs[0].IPv6Addr.String())
	if got.Less(netip.MustParseAddr("fd99::100")) || netip.MustParseAddr("fd99::1ff").Less(got) {
		t.Fatalf("advertised %s outside pool", got)
	}
	if !advPkt.dstIP.Equal(ll) {
		t.Errorf("reply sent to %s, want client link-local %s", advPkt.dstIP, ll)
	}

	// REQUEST -> REPLY with the same address, lease bound to the port.
	reqMsg, err := dhcpv6.NewRequestFromAdvertise(adv)
	if err != nil {
		t.Fatal(err)
	}
	reqFrame := craftUDP6(mac, net.HardwareAddr{0x33, 0x33, 0, 1, 0, 2}, ll, allRoutersDHCP6,
		dhcp6ClientPort, dhcp6ServerPort, reqMsg.ToBytes())
	sw.Deliver("vm1", reqFrame)

	repPkt := vm.waitFrame(t, "REPLY", func(p ingressPacket) bool {
		return p.isUDP6 && p.dstPort == dhcp6ClientPort
	})
	d, err = dhcpv6.FromBytes(repPkt.payload)
	if err != nil {
		t.Fatal(err)
	}
	rep := d.(*dhcpv6.Message)
	if rep.MessageType != dhcpv6.MessageTypeReply {
		t.Fatalf("got %s, want REPLY", rep.MessageType)
	}
	repIA := rep.Options.OneIANA()
	if repIA == nil || len(repIA.Options.Addresses()) != 1 || !repIA.Options.Addresses()[0].IPv6Addr.Equal(addrs[0].IPv6Addr) {
		t.Fatalf("REPLY IA mismatch: %v", repIA)
	}
	if repIA.IaId != sol.Options.OneIANA().IaId {
		t.Errorf("IAID not preserved")
	}

	leases := gw.DHCP6().Leases()
	if len(leases) != 1 || leases[0].PortID != "vm1" {
		t.Fatalf("leases = %+v", leases)
	}

	// Port down releases the v6 lease too.
	gw.PortDown("vm1")
	if got := len(gw.DHCP6().Leases()); got != 0 {
		t.Fatalf("leases after port down = %d, want 0", got)
	}
}

func TestDHCP6StaticBindingByDUID(t *testing.T) {
	sw, gw, vm := newV6TestGateway(t)

	if err := gw.DHCP6().SetConfig(DHCP6Config{
		Enabled:   true,
		PoolStart: netip.MustParseAddr("fd99::100"),
		PoolEnd:   netip.MustParseAddr("fd99::1ff"),
	}); err != nil {
		t.Fatal(err)
	}

	mac := net.HardwareAddr{0x02, 0, 0, 0, 0, 0x32}
	ll := net.ParseIP("fe80::32")
	frame, sol := solicitFrame(t, mac, ll)

	// Bind this client's DUID to a fixed address.
	duidHex := ""
	{
		b := sol.Options.ClientID().ToBytes()
		const hexdigits = "0123456789abcdef"
		for _, x := range b {
			duidHex += string(hexdigits[x>>4]) + string(hexdigits[x&0xf])
		}
	}
	if err := gw.DHCP6().PutStatic(StaticBinding{
		ID: "s1", ClientID: &duidHex, IP: netip.MustParseAddr("fd99::beef"),
	}); err != nil {
		t.Fatal(err)
	}

	sw.Deliver("vm1", frame)
	advPkt := vm.waitFrame(t, "ADVERTISE", func(p ingressPacket) bool {
		return p.isUDP6 && p.dstPort == dhcp6ClientPort
	})
	d, err := dhcpv6.FromBytes(advPkt.payload)
	if err != nil {
		t.Fatal(err)
	}
	adv := d.(*dhcpv6.Message)
	if got := adv.Options.OneIANA().Options.Addresses()[0].IPv6Addr.String(); got != "fd99::beef" {
		t.Fatalf("advertised %s, want fd99::beef (static binding)", got)
	}
}
