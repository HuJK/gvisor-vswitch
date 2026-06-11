package gateway_test

import (
	"context"
	"fmt"
	"net"
	"testing"
	"time"

	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/link/ethernet"
	"gvisor.dev/gvisor/pkg/tcpip/network/arp"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/icmp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"

	"github.com/HuJK/gvisor-vswitch/internal/api"
	"github.com/HuJK/gvisor-vswitch/internal/manager"
	"github.com/HuJK/gvisor-vswitch/internal/switchcore"
)

// vm is a guest simulated with its own netstack, attached to the switch as
// a regular port.
type vm struct {
	stk    *stack.Stack
	ep     *channel.Endpoint
	id     string
	sw     *switchcore.Switch
	cancel context.CancelFunc
}

func (v *vm) ID() string { return v.id }
func (v *vm) Send(_ switchcore.Meta, frame []byte) bool {
	pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{
		Payload: buffer.MakeWithData(frame),
	})
	v.ep.InjectInbound(0, pkt)
	pkt.DecRef()
	return true
}
func (v *vm) Close() error {
	v.cancel()
	v.ep.Close()
	return nil
}

func newVM(t *testing.T, sw *switchcore.Switch, id string, mac net.HardwareAddr, ipCIDR, gwIP string) *vm {
	t.Helper()
	s := stack.New(stack.Options{
		NetworkProtocols: []stack.NetworkProtocolFactory{
			ipv4.NewProtocol, ipv6.NewProtocol, arp.NewProtocol,
		},
		TransportProtocols: []stack.TransportProtocolFactory{
			tcp.NewProtocol, udp.NewProtocol, icmp.NewProtocol4,
		},
	})
	ch := channel.New(256, 1500, tcpip.LinkAddress(mac))
	if err := s.CreateNIC(1, ethernet.New(ch)); err != nil {
		t.Fatalf("vm CreateNIC: %v", err)
	}

	ip, ipNet, err := net.ParseCIDR(ipCIDR)
	if err != nil {
		t.Fatal(err)
	}
	prefixLen, _ := ipNet.Mask.Size()
	if err := s.AddProtocolAddress(1, tcpip.ProtocolAddress{
		Protocol: ipv4.ProtocolNumber,
		AddressWithPrefix: tcpip.AddressWithPrefix{
			Address:   tcpip.AddrFromSlice(ip.To4()),
			PrefixLen: prefixLen,
		},
	}, stack.AddressProperties{}); err != nil {
		t.Fatalf("vm AddProtocolAddress: %v", err)
	}

	localSub, err := tcpip.NewSubnet(
		tcpip.AddrFromSlice(ipNet.IP.To4()),
		tcpip.MaskFromBytes(ipNet.Mask),
	)
	if err != nil {
		t.Fatal(err)
	}
	s.SetRouteTable([]tcpip.Route{
		{Destination: localSub, NIC: 1},
		{Destination: header.IPv4EmptySubnet, Gateway: tcpip.AddrFromSlice(net.ParseIP(gwIP).To4()), NIC: 1},
	})

	ctx, cancel := context.WithCancel(context.Background())
	v := &vm{stk: s, ep: ch, id: id, sw: sw, cancel: cancel}
	go func() {
		for {
			pkt := ch.ReadContext(ctx)
			if pkt == nil {
				return
			}
			view := pkt.ToView()
			frame := append([]byte(nil), view.AsSlice()...)
			view.Release()
			pkt.DecRef()
			sw.Deliver(id, frame)
		}
	}()
	t.Cleanup(func() { s.Destroy() })
	return v
}

func (v *vm) dialTCP(addr string, port uint16) (net.Conn, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return gonet.DialContextTCP(ctx, v.stk, tcpip.FullAddress{
		Addr: tcpip.AddrFromSlice(net.ParseIP(addr).To4()),
		Port: port,
	}, ipv4.ProtocolNumber)
}

func setupGateway(t *testing.T, vlan int) (*manager.Manager, *vm) {
	t.Helper()
	m := manager.New()
	t.Cleanup(m.Close)

	_, err := m.CreateGateway(api.GatewayRequest{
		VLAN: vlan,
		IPv4: &api.GatewayV4{Address: "10.0.99.2", PrefixLen: 24},
		IPv6: &api.GatewayV6{Address: "fd99::2", PrefixLen: 64},
	})
	if err != nil {
		t.Fatalf("CreateGateway: %v", err)
	}

	v := newVM(t, m.Switch(), "vm1",
		net.HardwareAddr{0x02, 0, 0, 0, 0x99, 0x01},
		"10.0.99.100/24", "10.0.99.2")
	if err := m.Switch().AddPort(v, switchcore.PortAttrs{VLAN: vlan}); err != nil {
		t.Fatal(err)
	}
	return m, v
}

func TestRemoteForwardGuestToHost(t *testing.T) {
	m, v := setupGateway(t, 100)

	// Host-side echo server.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				buf := make([]byte, 64)
				n, _ := c.Read(buf)
				c.Write(append([]byte("echo:"), buf[:n]...))
			}(c)
		}
	}()

	// Guest connects to gateway:2222 -> forwarded to the host server.
	fwd, err := m.AddForward(100, api.ForwardRequest{
		Type: "remote", Network: "tcp",
		Bind: "10.0.99.2:2222", Host: ln.Addr().String(),
	})
	if err != nil {
		t.Fatalf("AddForward: %v", err)
	}

	conn, err := v.dialTCP("10.0.99.2", 2222)
	if err != nil {
		t.Fatalf("guest dial: %v", err)
	}
	conn.Write([]byte("hi"))
	buf := make([]byte, 64)
	conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	n, err := conn.Read(buf)
	if err != nil || string(buf[:n]) != "echo:hi" {
		t.Fatalf("guest read: %q err=%v", buf[:n], err)
	}
	conn.Close()

	// Forward list and deletion.
	fwds, err := m.ListForwards(100)
	if err != nil || len(fwds) != 1 {
		t.Fatalf("ListForwards = %v, %v", fwds, err)
	}
	if err := m.DeleteForward(100, fwd.ID); err != nil {
		t.Fatalf("DeleteForward: %v", err)
	}
	// Without the rule the gateway's own IP is firewalled -> dial fails.
	if c, err := v.dialTCP("10.0.99.2", 2222); err == nil {
		c.Close()
		t.Fatal("dial succeeded after forward removal")
	}
}

func TestLocalForwardHostToGuest(t *testing.T) {
	m, v := setupGateway(t, 100)

	// Guest-side echo server on the VM netstack.
	gln, err := gonet.ListenTCP(v.stk, tcpip.FullAddress{
		Addr: tcpip.AddrFromSlice(net.ParseIP("10.0.99.100").To4()),
		Port: 8080,
	}, ipv4.ProtocolNumber)
	if err != nil {
		t.Fatal(err)
	}
	defer gln.Close()
	go func() {
		for {
			c, err := gln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				buf := make([]byte, 64)
				n, _ := c.Read(buf)
				c.Write(append([]byte("guest:"), buf[:n]...))
			}(c)
		}
	}()

	// Pick a free host port.
	tmp, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	hostBind := tmp.Addr().String()
	tmp.Close()

	fwd, err := m.AddForward(100, api.ForwardRequest{
		Type: "local", Network: "tcp",
		Bind: hostBind, Host: "10.0.99.100:8080",
	})
	if err != nil {
		t.Fatalf("AddForward: %v", err)
	}

	conn, err := net.DialTimeout("tcp", hostBind, 3*time.Second)
	if err != nil {
		t.Fatalf("host dial: %v", err)
	}
	conn.Write([]byte("yo"))
	buf := make([]byte, 64)
	conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	n, err := conn.Read(buf)
	if err != nil || string(buf[:n]) != "guest:yo" {
		t.Fatalf("host read: %q err=%v", buf[:n], err)
	}
	conn.Close()

	// Deleting the forward frees the host port.
	if err := m.DeleteForward(100, fwd.ID); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(2 * time.Second)
	for {
		c, err := net.DialTimeout("tcp", hostBind, 200*time.Millisecond)
		if err != nil {
			break
		}
		c.Close()
		if time.Now().After(deadline) {
			t.Fatal("host port still listening after forward removal")
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func TestGatewayLifecycle(t *testing.T) {
	m := manager.New()
	t.Cleanup(m.Close)

	if _, err := m.CreateGateway(api.GatewayRequest{VLAN: 5}); err == nil {
		t.Error("gateway without ipv4/ipv6 accepted")
	}

	info, err := m.CreateGateway(api.GatewayRequest{
		VLAN: 5,
		IPv4: &api.GatewayV4{Address: "192.168.5.1", PrefixLen: 24},
	})
	if err != nil {
		t.Fatal(err)
	}
	if info.MACEffective == "" {
		t.Error("no effective MAC")
	}

	if _, err := m.CreateGateway(api.GatewayRequest{
		VLAN: 5,
		IPv4: &api.GatewayV4{Address: "192.168.6.1", PrefixLen: 24},
	}); err == nil {
		t.Error("duplicate vlan gateway accepted")
	}

	if got := len(m.ListGateways()); got != 1 {
		t.Errorf("ListGateways = %d, want 1", got)
	}
	if err := m.DeleteGateway(5); err != nil {
		t.Fatal(err)
	}
	if err := m.DeleteGateway(5); err == nil {
		t.Error("double delete succeeded")
	}

	// VLAN is free again.
	if _, err := m.CreateGateway(api.GatewayRequest{
		VLAN: 5,
		IPv4: &api.GatewayV4{Address: "192.168.5.1", PrefixLen: 24},
	}); err != nil {
		t.Errorf("recreate after delete: %v", err)
	}
}

var _ = fmt.Sprintf

func TestReplaceForwardsReconcile(t *testing.T) {
	m, _ := setupGateway(t, 100)

	// Seed: two forwards.
	keep, err := m.AddForward(100, api.ForwardRequest{
		Type: "remote", Network: "tcp", Bind: "10.0.99.2:25", Host: "127.0.0.1:1025"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := m.AddForward(100, api.ForwardRequest{
		Type: "remote", Network: "tcp", Bind: "10.0.99.2:26", Host: "127.0.0.1:1026"}); err != nil {
		t.Fatal(err)
	}

	// Desired set: keep :25, drop :26, add :27.
	out, err := m.ReplaceForwards(100, []api.ForwardRequest{
		{Type: "remote", Network: "tcp", Bind: "10.0.99.2:25", Host: "127.0.0.1:1025"},
		{Type: "remote", Network: "tcp", Bind: "10.0.99.2:27", Host: "127.0.0.1:1027"},
	})
	if err != nil {
		t.Fatalf("ReplaceForwards: %v", err)
	}
	if len(out) != 2 {
		t.Fatalf("result = %+v, want 2 rules", out)
	}
	binds := map[string]string{}
	for _, f := range out {
		binds[f.Bind] = f.ID
	}
	if _, ok := binds["10.0.99.2:26"]; ok {
		t.Error(":26 not removed")
	}
	if _, ok := binds["10.0.99.2:27"]; !ok {
		t.Error(":27 not added")
	}
	// The kept rule was not recreated: same ID.
	if binds["10.0.99.2:25"] != keep.ID {
		t.Errorf("kept rule recreated: id %s -> %s", keep.ID, binds["10.0.99.2:25"])
	}

	// Duplicate tuples rejected.
	if _, err := m.ReplaceForwards(100, []api.ForwardRequest{
		{Type: "remote", Network: "tcp", Bind: "10.0.99.2:25", Host: "127.0.0.1:1025"},
		{Type: "remote", Network: "tcp", Bind: "10.0.99.2:25", Host: "127.0.0.1:1025"},
	}); err == nil {
		t.Error("duplicate desired tuple accepted")
	}

	// Empty set clears everything.
	out, err = m.ReplaceForwards(100, nil)
	if err != nil || len(out) != 0 {
		t.Fatalf("clear: %v %+v", err, out)
	}
}

func TestReplaceDHCPStatic(t *testing.T) {
	m, _ := setupGateway(t, 100)
	mac1, mac2 := "02:00:00:00:00:01", "02:00:00:00:00:02"

	if err := m.ReplaceDHCPStatic(100, 4, []api.DHCPStaticBinding{
		{ID: "a", MAC: &mac1, IP: "10.0.99.10"},
		{ID: "b", MAC: &mac2, IP: "10.0.99.11"},
	}); err != nil {
		t.Fatal(err)
	}
	bs, _ := m.ListDHCPStatic(100, 4)
	if len(bs) != 2 {
		t.Fatalf("statics = %+v", bs)
	}

	// Replace with a single different set: old entries gone.
	if err := m.ReplaceDHCPStatic(100, 4, []api.DHCPStaticBinding{
		{ID: "c", MAC: &mac1, IP: "10.0.99.12"},
	}); err != nil {
		t.Fatal(err)
	}
	bs, _ = m.ListDHCPStatic(100, 4)
	if len(bs) != 1 || bs[0].ID != "c" {
		t.Fatalf("statics after replace = %+v", bs)
	}

	// Validation failure leaves the current set untouched.
	if err := m.ReplaceDHCPStatic(100, 4, []api.DHCPStaticBinding{
		{ID: "x", MAC: &mac1, IP: "10.0.99.13"},
		{ID: "x", MAC: &mac2, IP: "10.0.99.14"}, // duplicate id
	}); err == nil {
		t.Fatal("duplicate ids accepted")
	}
	bs, _ = m.ListDHCPStatic(100, 4)
	if len(bs) != 1 || bs[0].ID != "c" {
		t.Fatalf("set changed despite validation failure: %+v", bs)
	}

	// Empty set clears.
	if err := m.ReplaceDHCPStatic(100, 4, nil); err != nil {
		t.Fatal(err)
	}
	if bs, _ = m.ListDHCPStatic(100, 4); len(bs) != 0 {
		t.Fatalf("statics not cleared: %+v", bs)
	}
}
