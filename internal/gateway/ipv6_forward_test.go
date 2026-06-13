package gateway_test

import (
	"context"
	"net"
	"testing"
	"time"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
	"gvisor.dev/gvisor/pkg/tcpip/stack"

	"github.com/HuJK/gvisor-vswitch/internal/api"
)

// addV6 gives the VM stack a global IPv6 address in fd99::/64 plus an on-link
// route, so it can reach the gateway (fd99::2) directly via NDP.
func addV6(t *testing.T, v *vm, addr string) {
	t.Helper()
	a := tcpip.AddrFromSlice(net.ParseIP(addr).To16())
	if err := v.stk.AddProtocolAddress(1, tcpip.ProtocolAddress{
		Protocol: ipv6.ProtocolNumber,
		AddressWithPrefix: tcpip.AddressWithPrefix{Address: a, PrefixLen: 64},
	}, stack.AddressProperties{}); err != nil {
		t.Fatalf("vm add v6 addr: %v", err)
	}
	_, ipNet, err := net.ParseCIDR("fd99::/64")
	if err != nil {
		t.Fatal(err)
	}
	sub, err := tcpip.NewSubnet(tcpip.AddrFromSlice(ipNet.IP), tcpip.MaskFromBytes(ipNet.Mask))
	if err != nil {
		t.Fatal(err)
	}
	rt := v.stk.GetRouteTable()
	rt = append(rt, tcpip.Route{Destination: sub, NIC: 1})
	v.stk.SetRouteTable(rt)
}

func (v *vm) dialTCP6(addr string, port uint16) (net.Conn, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return gonet.DialContextTCP(ctx, v.stk, tcpip.FullAddress{
		Addr: tcpip.AddrFromSlice(net.ParseIP(addr).To16()),
		Port: port,
	}, ipv6.ProtocolNumber)
}

// TestRemoteForwardGuestToHostV6: guest connects to the gateway's IPv6 address
// and is forwarded to a host-side TCP server.
func TestRemoteForwardGuestToHostV6(t *testing.T) {
	m, v := setupGateway(t, 100)
	addV6(t, v, "fd99::100")

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

	if _, err := m.AddForward(100, api.ForwardRequest{
		Type: "remote", Network: "tcp",
		Bind: "[fd99::2]:2222", Host: ln.Addr().String(),
	}); err != nil {
		t.Fatalf("AddForward: %v", err)
	}

	conn, err := v.dialTCP6("fd99::2", 2222)
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
}

// TestRemoteForwardGuestToHostV6ToV6Host: guest connects to the gateway's IPv6
// address and is forwarded to an IPv6 (::1) host-side server, exercising the
// host-side IPv6 dial path.
func TestRemoteForwardGuestToHostV6ToV6Host(t *testing.T) {
	m, v := setupGateway(t, 100)
	addV6(t, v, "fd99::100")

	ln, err := net.Listen("tcp", "[::1]:0")
	if err != nil {
		t.Skipf("no IPv6 loopback on host: %v", err)
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
				c.Write(append([]byte("echo6:"), buf[:n]...))
			}(c)
		}
	}()

	if _, err := m.AddForward(100, api.ForwardRequest{
		Type: "remote", Network: "tcp",
		Bind: "[fd99::2]:2223", Host: ln.Addr().String(),
	}); err != nil {
		t.Fatalf("AddForward: %v", err)
	}

	conn, err := v.dialTCP6("fd99::2", 2223)
	if err != nil {
		t.Fatalf("guest dial: %v", err)
	}
	conn.Write([]byte("hi"))
	buf := make([]byte, 64)
	conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	n, err := conn.Read(buf)
	if err != nil || string(buf[:n]) != "echo6:hi" {
		t.Fatalf("guest read: %q err=%v", buf[:n], err)
	}
	conn.Close()
}

// TestLocalForwardHostToGuestV6: host listens, connections are forwarded into
// the guest over IPv6. This exercises the gateway's outbound NDP path.
func TestLocalForwardHostToGuestV6(t *testing.T) {
	m, v := setupGateway(t, 100)
	addV6(t, v, "fd99::100")

	gln, err := gonet.ListenTCP(v.stk, tcpip.FullAddress{
		Addr: tcpip.AddrFromSlice(net.ParseIP("fd99::100").To16()),
		Port: 8080,
	}, ipv6.ProtocolNumber)
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

	tmp, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	hostBind := tmp.Addr().String()
	tmp.Close()

	if _, err := m.AddForward(100, api.ForwardRequest{
		Type: "local", Network: "tcp",
		Bind: hostBind, Host: "[fd99::100]:8080",
	}); err != nil {
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
}

// TestLocalForwardHostToGuestV6UDP: same as above but UDP, which has no
// connect handshake to drive neighbor resolution, so the first datagram
// depends on the gateway having (or priming) the guest's NDP entry.
func TestLocalForwardHostToGuestV6UDP(t *testing.T) {
	m, v := setupGateway(t, 100)
	addV6(t, v, "fd99::100")

	gconn, err := gonet.DialUDP(v.stk, &tcpip.FullAddress{
		Addr: tcpip.AddrFromSlice(net.ParseIP("fd99::100").To16()),
		Port: 9090,
	}, nil, ipv6.ProtocolNumber)
	if err != nil {
		t.Fatal(err)
	}
	defer gconn.Close()
	go func() {
		buf := make([]byte, 64)
		for {
			n, addr, err := gconn.ReadFrom(buf)
			if err != nil {
				return
			}
			gconn.WriteTo(append([]byte("guest:"), buf[:n]...), addr)
		}
	}()

	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	hostBind := pc.LocalAddr().String()
	pc.Close()

	if _, err := m.AddForward(100, api.ForwardRequest{
		Type: "local", Network: "udp",
		Bind: hostBind, Host: "[fd99::100]:9090",
	}); err != nil {
		t.Fatalf("AddForward: %v", err)
	}

	c, err := net.Dial("udp", hostBind)
	if err != nil {
		t.Fatalf("host dial: %v", err)
	}
	defer c.Close()
	buf := make([]byte, 64)
	var got string
	c.Write([]byte("yo")) // single shot: no retry to drive NDP
	c.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, err := c.Read(buf)
	if err == nil {
		got = string(buf[:n])
	}
	if got != "guest:yo" {
		t.Fatalf("host read: %q err=%v (first datagram lost?)", got, err)
	}
}
