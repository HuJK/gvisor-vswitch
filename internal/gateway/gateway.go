// Package gateway implements the per-VLAN virtual gateway: a gVisor
// netstack attached to the switch as an internal L2 port, reusing
// slirpnetstack's NAT/forwarding machinery, plus (in-process) DHCP and
// router-advertisement services.
package gateway

import (
	"context"
	"fmt"
	"net"
	"sync"

	sns "github.com/cloudflare/slirpnetstack"
	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/link/ethernet"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/icmp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"

	"github.com/HuJK/gvisor-vswitch/internal/switchcore"
)

const (
	nicID      = tcpip.NICID(1)
	bufSize    = 4 * 1024 * 1024
	txQueueLen = 512
	// channelQueueLen is the outbound (stack -> switch) packet queue.
	channelQueueLen = 512
)

// V4Config is the gateway's IPv4 side.
type V4Config struct {
	Address   net.IP
	PrefixLen int
}

// V6Config is the gateway's IPv6 side.
type V6Config struct {
	Address   net.IP
	PrefixLen int
	LinkLocal net.IP // optional; default EUI-64 from MAC
}

// Config creates a Gateway.
type Config struct {
	PortID string
	MAC    net.HardwareAddr // optional
	MTU    uint32           // optional, default 1500

	IPv4 *V4Config
	IPv6 *V6Config

	EnableInternetRouting bool
	EnableHostRouting     bool
	Allow                 []string
	Deny                  []string

	// DNSProxy: serve DNS on the gateway addresses :53 through the host
	// system resolver.
	DNSProxy bool
}

// FrameHandler inspects an ingress frame before it reaches the netstack
// (DHCP, router solicitations). Returning true consumes the frame.
type FrameHandler func(meta switchcore.Meta, frame []byte) bool

type inFrame struct {
	meta  switchcore.Meta
	frame []byte
}

// Gateway is a netstack-backed switchport. It implements switchcore.Port.
type Gateway struct {
	cfg Config
	sw  *switchcore.Switch
	ref *switchcore.PortRef

	stk   *stack.Stack
	ep    *channel.Endpoint
	state *sns.State

	linkLocal tcpip.Address

	handlerMu sync.RWMutex
	handlers  []FrameHandler

	txq    chan inFrame
	ctx    context.Context
	cancel context.CancelFunc
	once   sync.Once

	fwdMu    sync.Mutex
	fwdSeq   int
	forwards map[string]*forwardRec
	fwdTable *sns.DynFwdTable

	dhcp4 *dhcp4Server
	dhcp6 *dhcp6Server
	ra    *raServer
}

// New builds the gateway stack and starts its pumps. The caller registers
// the returned Gateway as a switchport.
func New(sw *switchcore.Switch, cfg Config) (*Gateway, error) {
	if cfg.IPv4 == nil && cfg.IPv6 == nil {
		return nil, fmt.Errorf("gateway needs at least one of ipv4/ipv6")
	}
	if cfg.MTU == 0 {
		cfg.MTU = 1500
	}
	if cfg.MAC == nil {
		return nil, fmt.Errorf("gateway MAC must be set")
	}

	var natRange4, natRange6 string
	if cfg.IPv4 != nil {
		if cfg.IPv4.Address.To4() == nil {
			return nil, fmt.Errorf("ipv4 address %s is not IPv4", cfg.IPv4.Address)
		}
		natRange4 = fmt.Sprintf("%s/%d", cfg.IPv4.Address, cfg.IPv4.PrefixLen)
	}
	if cfg.IPv6 != nil {
		if cfg.IPv6.Address.To4() != nil || cfg.IPv6.Address.To16() == nil {
			return nil, fmt.Errorf("ipv6 address %s is not IPv6", cfg.IPv6.Address)
		}
		natRange6 = fmt.Sprintf("%s/%d", cfg.IPv6.Address, cfg.IPv6.PrefixLen)
	}

	var allow, deny sns.IPPortRangeSlice
	for _, a := range cfg.Allow {
		if err := allow.Set(a); err != nil {
			return nil, fmt.Errorf("bad allow range %q: %w", a, err)
		}
	}
	for _, d := range cfg.Deny {
		if err := deny.Set(d); err != nil {
			return nil, fmt.Errorf("bad deny range %q: %w", d, err)
		}
	}

	// Link-local address (needed for any IPv6 activity, including RA).
	llOverride := ""
	if cfg.IPv6 != nil && cfg.IPv6.LinkLocal != nil {
		llOverride = cfg.IPv6.LinkLocal.String()
	}
	linkLocal, err := sns.ResolveLinkLocalV6(llOverride, cfg.MAC)
	if err != nil {
		return nil, err
	}

	state := sns.NewGatewayState(sns.GatewayStateOpts{
		NatRange4:             natRange4,
		NatRange6:             natRange6,
		EnableHostRouting:     cfg.EnableHostRouting,
		EnableInternetRouting: cfg.EnableInternetRouting,
		AllowRange:            allow,
		DenyRange:             deny,
	})

	s := sns.NewStack(bufSize, bufSize)

	gwAddrs := sns.NewLocalAddrs(linkLocal)
	if cfg.IPv4 != nil {
		sns.LocalAddrsAdd(gwAddrs, tcpip.AddrFromSlice(cfg.IPv4.Address.To4()))
	}
	if cfg.IPv6 != nil {
		sns.LocalAddrsAdd(gwAddrs, tcpip.AddrFromSlice(cfg.IPv6.Address.To16()))
	}

	g := &Gateway{
		cfg:       cfg,
		sw:        sw,
		ref:       sw.Ref(cfg.PortID),
		stk:       s,
		state:     state,
		linkLocal: linkLocal,
		txq:       make(chan inFrame, txQueueLen),
		forwards:  make(map[string]*forwardRec),
		fwdTable:  sns.NewDynFwdTable(),
	}
	g.ctx, g.cancel = context.WithCancel(context.Background())

	var dnsProxy *sns.DNSProxy
	if cfg.DNSProxy {
		var dnsIPs []net.IP
		if cfg.IPv4 != nil {
			dnsIPs = append(dnsIPs, cfg.IPv4.Address)
		}
		if cfg.IPv6 != nil {
			dnsIPs = append(dnsIPs, cfg.IPv6.Address)
		}
		if len(dnsIPs) > 0 {
			dnsProxy = sns.NewDNSProxy(dnsIPs)
		}
	}

	// Transport handlers: dynamic forward tables + transparent routing.
	fwdTcp := tcp.NewForwarder(s, 0, 10, sns.DynTcpRoutingHandler(state, g.fwdTable, dnsProxy))
	s.SetTransportProtocolHandler(tcp.ProtocolNumber, fwdTcp.HandlePacket)
	fwdUdp := udp.NewForwarder(s, sns.DynUdpRoutingHandler(s, state, g.fwdTable, dnsProxy))
	s.SetTransportProtocolHandler(udp.ProtocolNumber, fwdUdp.HandlePacket)

	// ICMP echo: answer for the gateway's own addresses (the netstack
	// synthesizes the reply) and relay everything else to the real network
	// through the slirpnetstack PingForwarder (host ping sockets with TTL
	// passthrough and ICMP error translation, so ping and ICMP traceroute
	// work through the gateway, subject to the same routing firewall as
	// TCP/UDP).
	var gwAddr4, gwAddr6 tcpip.Address
	if cfg.IPv4 != nil {
		gwAddr4 = tcpip.AddrFromSlice(cfg.IPv4.Address.To4())
	}
	if cfg.IPv6 != nil {
		gwAddr6 = tcpip.AddrFromSlice(cfg.IPv6.Address.To16())
	}
	pingFwd := sns.NewPingForwarder(s, nicID, state, gwAddr4, gwAddr6)
	icmpEchoHandler := func(id stack.TransportEndpointID, pkt *stack.PacketBuffer) bool {
		if gwAddrs.Has(id.LocalAddress) {
			return false
		}
		return pingFwd.HandlePacket(id, pkt)
	}
	s.SetTransportProtocolHandler(icmp.ProtocolNumber4, icmpEchoHandler)
	s.SetTransportProtocolHandler(icmp.ProtocolNumber6, icmpEchoHandler)

	// Link chain: stack <- hostfilter <- ethernet <- channel.
	g.ep = channel.New(channelQueueLen, cfg.MTU, tcpip.LinkAddress(cfg.MAC))
	// Guests offload TCP/UDP checksums to the virtio NIC, so frames
	// arriving through tap/af_xdp carry uncomputed (partial) checksums.
	// This stack is that "hardware": skip RX checksum validation or every
	// guest TCP/UDP segment is silently dropped (ICMP and the pre-stack
	// DHCP handler are unaffected, which makes it look like a working
	// network that resolves and connects nothing).
	g.ep.LinkEPCapabilities |= stack.CapabilityRXChecksumOffload
	var linkEP stack.LinkEndpoint = ethernet.New(g.ep)
	linkEP = sns.NewHostFilter(linkEP, gwAddrs)

	if err := sns.CreateNIC(s, nicID, linkEP); err != nil {
		s.Destroy()
		return nil, fmt.Errorf("create NIC: %w", err)
	}

	if natRange4 != "" {
		sns.StackRoutingSetup(s, nicID, natRange4)
	}
	if natRange6 != "" {
		sns.StackRoutingSetup(s, nicID, natRange6)
	}
	sns.StackAssignAddr6(s, nicID, linkLocal, 64)

	g.dhcp4 = newDHCP4Server(g)
	g.dhcp6 = newDHCP6Server(g)
	g.ra = newRAServer(g)

	go g.rxPump()
	go g.txWorker()
	return g, nil
}

// DHCP4 exposes the gateway's DHCPv4 server.
func (g *Gateway) DHCP4() *dhcp4Server { return g.dhcp4 }

// DHCP6 exposes the gateway's DHCPv6 server.
func (g *Gateway) DHCP6() *dhcp6Server { return g.dhcp6 }

// RA exposes the gateway's router-advertisement service.
func (g *Gateway) RA() *raServer { return g.ra }

// PortDown releases DHCP leases tied to a switchport that went offline.
func (g *Gateway) PortDown(portID string) {
	g.dhcp4.PortDown(portID)
	g.dhcp6.PortDown(portID)
}

// rxPump moves outbound packets (stack -> switch).
func (g *Gateway) rxPump() {
	for {
		pkt := g.ep.ReadContext(g.ctx)
		if pkt == nil {
			return
		}
		view := pkt.ToView()
		frame := append([]byte(nil), view.AsSlice()...)
		view.Release()
		pkt.DecRef()
		g.ref.Deliver(frame)
	}
}

// txWorker injects inbound frames (switch -> stack), running frame handlers
// (DHCP/RS interceptors) outside the switch lock.
func (g *Gateway) txWorker() {
	for {
		select {
		case <-g.ctx.Done():
			return
		case in := <-g.txq:
			if g.runHandlers(in) {
				continue
			}
			pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{
				Payload: buffer.MakeWithData(in.frame),
			})
			g.ep.InjectInbound(0, pkt)
			pkt.DecRef()
		}
	}
}

func (g *Gateway) runHandlers(in inFrame) bool {
	g.handlerMu.RLock()
	hs := g.handlers
	g.handlerMu.RUnlock()
	for _, h := range hs {
		if h(in.meta, in.frame) {
			return true
		}
	}
	return false
}

// AddFrameHandler registers an ingress interceptor (DHCP, RS).
func (g *Gateway) AddFrameHandler(h FrameHandler) {
	g.handlerMu.Lock()
	g.handlers = append(g.handlers, h)
	g.handlerMu.Unlock()
}

// InjectFrame hands a crafted frame (DHCP reply, RA) to the switch as if
// the gateway stack had emitted it.
func (g *Gateway) InjectFrame(frame []byte) {
	g.ref.Deliver(frame)
}

// Config accessors used by the DHCP/RA services and the manager.

func (g *Gateway) IPv4() *V4Config          { return g.cfg.IPv4 }
func (g *Gateway) IPv6() *V6Config          { return g.cfg.IPv6 }
func (g *Gateway) MAC() net.HardwareAddr    { return g.cfg.MAC }
func (g *Gateway) MTU() uint32              { return g.cfg.MTU }
func (g *Gateway) LinkLocal() net.IP        { return net.IP(g.linkLocal.AsSlice()) }
func (g *Gateway) Context() context.Context { return g.ctx }

// switchcore.Port implementation.

func (g *Gateway) ID() string { return g.cfg.PortID }

func (g *Gateway) Send(meta switchcore.Meta, frame []byte) bool {
	select {
	case <-g.ctx.Done():
		return false
	default:
	}
	select {
	case g.txq <- inFrame{meta: meta, frame: frame}:
		return true
	default:
		return false
	}
}

func (g *Gateway) Close() error {
	g.once.Do(func() {
		g.cancel()
		g.closeForwards()
		g.ep.Close()
		g.stk.Destroy()
	})
	return nil
}
