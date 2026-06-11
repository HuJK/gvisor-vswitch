package gateway

import (
	"encoding/hex"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/insomniacslk/dhcp/dhcpv4"

	"github.com/HuJK/gvisor-vswitch/internal/switchcore"
)

const (
	dhcp4ServerPort = 67
	dhcp4ClientPort = 68

	defaultLeaseTime = time.Hour
	leaseSweepEvery  = 30 * time.Second
)

var (
	broadcastMAC = net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}
	broadcastIP4 = net.IPv4bcast
)

// DHCP4Config is the gateway-side DHCPv4 server configuration.
type DHCP4Config struct {
	Enabled   bool
	PoolStart netip.Addr
	PoolEnd   netip.Addr
	LeaseTime time.Duration
	DNS       []net.IP
}

// dhcp4Server answers DHCPv4 at L2, before the netstack, so it can use the
// source switchport identity for static bindings and lease/port linkage.
type dhcp4Server struct {
	gw *Gateway

	mu      sync.Mutex
	cfg     DHCP4Config
	statics map[string]*StaticBinding

	leases *leaseTable
}

func newDHCP4Server(gw *Gateway) *dhcp4Server {
	s := &dhcp4Server{
		gw:      gw,
		statics: make(map[string]*StaticBinding),
		leases:  newLeaseTable(),
	}
	gw.AddFrameHandler(s.handleFrame)
	go s.sweepLoop()
	return s
}

func (s *dhcp4Server) sweepLoop() {
	t := time.NewTicker(leaseSweepEvery)
	defer t.Stop()
	for {
		select {
		case <-s.gw.Context().Done():
			return
		case <-t.C:
			s.leases.expireSweep()
		}
	}
}

// SetConfig validates and applies the server configuration.
func (s *dhcp4Server) SetConfig(cfg DHCP4Config) error {
	if cfg.Enabled {
		v4 := s.gw.IPv4()
		if v4 == nil {
			return fmt.Errorf("gateway has no IPv4 network")
		}
		if !cfg.PoolStart.Is4() || !cfg.PoolEnd.Is4() {
			return fmt.Errorf("dhcp4 pool must be IPv4 addresses")
		}
		if cfg.PoolEnd.Less(cfg.PoolStart) {
			return fmt.Errorf("pool_end is before pool_start")
		}
		network := gatewayNet4(v4)
		if !network.Contains(cfg.PoolStart) || !network.Contains(cfg.PoolEnd) {
			return fmt.Errorf("pool [%s, %s] is not inside the gateway network %s", cfg.PoolStart, cfg.PoolEnd, network)
		}
		if cfg.LeaseTime <= 0 {
			cfg.LeaseTime = defaultLeaseTime
		}
		if len(cfg.DNS) == 0 {
			cfg.DNS = []net.IP{v4.Address}
		}
	}
	s.mu.Lock()
	s.cfg = cfg
	s.mu.Unlock()
	return nil
}

func (s *dhcp4Server) Config() DHCP4Config {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.cfg
}

func gatewayNet4(v4 *V4Config) netip.Prefix {
	addr, _ := netip.AddrFromSlice(v4.Address.To4())
	return netip.PrefixFrom(addr, v4.PrefixLen).Masked()
}

// Static binding CRUD.

func (s *dhcp4Server) PutStatic(b StaticBinding) error {
	if err := b.validate(); err != nil {
		return err
	}
	if !b.IP.Is4() {
		return fmt.Errorf("dhcp4 static binding ip must be IPv4")
	}
	s.mu.Lock()
	s.statics[b.ID] = &b
	s.mu.Unlock()
	return nil
}

func (s *dhcp4Server) ListStatic() []StaticBinding {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]StaticBinding, 0, len(s.statics))
	for _, b := range s.statics {
		out = append(out, *b)
	}
	return out
}

func (s *dhcp4Server) DeleteStatic(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.statics[id]; !ok {
		return fmt.Errorf("static binding %q not found", id)
	}
	delete(s.statics, id)
	return nil
}

// Leases returns active leases; ReleaseLease force-releases one.
func (s *dhcp4Server) Leases() []Lease { return s.leases.snapshot() }

func (s *dhcp4Server) ReleaseLease(ip netip.Addr) error {
	if !s.leases.release(ip) {
		return fmt.Errorf("lease %s not found", ip)
	}
	return nil
}

// PortDown releases all leases tied to a switchport.
func (s *dhcp4Server) PortDown(portID string) {
	s.leases.releaseByPort(portID)
}

// handleFrame intercepts UDP :67 frames.
func (s *dhcp4Server) handleFrame(meta switchcore.Meta, frame []byte) bool {
	pkt, ok := parseIngress(frame)
	if !ok || !pkt.isUDP4 || pkt.dstPort != dhcp4ServerPort {
		return false
	}
	// Consume DHCP traffic even when disabled: the netstack has no DHCP
	// service either.
	s.mu.Lock()
	cfg := s.cfg
	s.mu.Unlock()
	if !cfg.Enabled {
		return true
	}

	req, err := dhcpv4.FromBytes(pkt.payload)
	if err != nil || req.OpCode != dhcpv4.OpcodeBootRequest {
		return true
	}

	switch req.MessageType() {
	case dhcpv4.MessageTypeDiscover:
		s.replyToDiscover(meta, cfg, req)
	case dhcpv4.MessageTypeRequest:
		s.replyToRequest(meta, cfg, req)
	case dhcpv4.MessageTypeRelease:
		if ip, ok := netip.AddrFromSlice(req.ClientIPAddr.To4()); ok && ip.IsValid() {
			s.leases.release(ip)
		}
	case dhcpv4.MessageTypeDecline:
		if ip, ok := netip.AddrFromSlice(req.RequestedIPAddress().To4()); ok && ip.IsValid() {
			// Mark declined addresses unusable for a while by leasing
			// them to a placeholder.
			s.leases.set(Lease{IP: ip, MAC: "declined", Expiry: time.Now().Add(cfg.LeaseTime)})
		}
	}
	return true
}

func clientIDOf(req *dhcpv4.DHCPv4) string {
	return hex.EncodeToString(req.Options.Get(dhcpv4.OptionClientIdentifier))
}

// selectIP picks (and books) the address for a client following static
// bindings, the existing lease, then the pool. Returns the invalid Addr if
// nothing can be offered.
func (s *dhcp4Server) selectIP(meta switchcore.Meta, cfg DHCP4Config, req *dhcpv4.DHCPv4) netip.Addr {
	mac := req.ClientHWAddr.String()
	cid := clientIDOf(req)
	v4 := s.gw.IPv4()
	gwIP, _ := netip.AddrFromSlice(v4.Address.To4())

	s.mu.Lock()
	bindings := make([]*StaticBinding, 0, len(s.statics))
	for _, b := range s.statics {
		bindings = append(bindings, b)
	}
	s.mu.Unlock()

	staticIPs := make(map[netip.Addr]bool, len(bindings))
	for _, b := range bindings {
		staticIPs[b.IP] = true
	}

	lease := Lease{
		MAC:      mac,
		ClientID: cid,
		PortID:   meta.SrcPortID,
		Expiry:   time.Now().Add(cfg.LeaseTime),
	}

	if b := matchBinding(bindings, meta.SrcPortID, mac, cid); b != nil {
		if s.leases.inUse(b.IP, mac, cid) {
			return netip.Addr{}
		}
		lease.IP = b.IP
		lease.Static = true
		s.leases.set(lease)
		return b.IP
	}

	if cur := s.leases.byClient(mac, cid); cur != nil && !staticIPs[cur.IP] {
		lease.IP = cur.IP
		s.leases.set(lease)
		return cur.IP
	}

	// Honor a requested address when it is free and inside the pool.
	if rip, ok := netip.AddrFromSlice(req.RequestedIPAddress().To4()); ok && rip.IsValid() {
		if !cfg.PoolEnd.Less(rip) && !rip.Less(cfg.PoolStart) && rip != gwIP && !staticIPs[rip] && !s.leases.inUse(rip, mac, cid) {
			lease.IP = rip
			s.leases.set(lease)
			return rip
		}
	}

	return s.leases.allocate(cfg.PoolStart, cfg.PoolEnd, func(ip netip.Addr) bool {
		return ip == gwIP || staticIPs[ip]
	}, lease)
}

func (s *dhcp4Server) replyToDiscover(meta switchcore.Meta, cfg DHCP4Config, req *dhcpv4.DHCPv4) {
	ip := s.selectIP(meta, cfg, req)
	if !ip.IsValid() {
		return // pool exhausted: stay silent
	}
	s.sendReply(cfg, req, dhcpv4.MessageTypeOffer, ip)
}

func (s *dhcp4Server) replyToRequest(meta switchcore.Meta, cfg DHCP4Config, req *dhcpv4.DHCPv4) {
	// The address the client asks for: option 50 (SELECTING/INIT-REBOOT)
	// or ciaddr (RENEWING/REBINDING).
	want, ok := netip.AddrFromSlice(req.RequestedIPAddress().To4())
	if !ok || !want.IsValid() || want.IsUnspecified() {
		want, ok = netip.AddrFromSlice(req.ClientIPAddr.To4())
		if !ok || !want.IsValid() || want.IsUnspecified() {
			s.sendNak(cfg, req)
			return
		}
	}
	got := s.selectIP(meta, cfg, req)
	if !got.IsValid() || got != want {
		s.sendNak(cfg, req)
		return
	}
	s.sendReply(cfg, req, dhcpv4.MessageTypeAck, got)
}

func (s *dhcp4Server) sendReply(cfg DHCP4Config, req *dhcpv4.DHCPv4, typ dhcpv4.MessageType, ip netip.Addr) {
	v4 := s.gw.IPv4()
	mask := net.CIDRMask(v4.PrefixLen, 32)

	reply, err := dhcpv4.NewReplyFromRequest(req,
		dhcpv4.WithMessageType(typ),
		dhcpv4.WithServerIP(v4.Address),
		dhcpv4.WithOption(dhcpv4.OptServerIdentifier(v4.Address)),
		dhcpv4.WithOption(dhcpv4.OptSubnetMask(mask)),
		dhcpv4.WithOption(dhcpv4.OptRouter(v4.Address)),
		dhcpv4.WithOption(dhcpv4.OptDNS(cfg.DNS...)),
		dhcpv4.WithOption(dhcpv4.OptIPAddressLeaseTime(cfg.LeaseTime)),
		dhcpv4.WithOption(dhcpv4.OptRenewTimeValue(cfg.LeaseTime/2)),
		dhcpv4.WithOption(dhcpv4.OptRebindingTimeValue(cfg.LeaseTime*7/8)),
	)
	if err != nil {
		return
	}
	reply.YourIPAddr = ip.AsSlice()
	s.transmit(req, reply, ip)
}

func (s *dhcp4Server) sendNak(cfg DHCP4Config, req *dhcpv4.DHCPv4) {
	v4 := s.gw.IPv4()
	reply, err := dhcpv4.NewReplyFromRequest(req,
		dhcpv4.WithMessageType(dhcpv4.MessageTypeNak),
		dhcpv4.WithOption(dhcpv4.OptServerIdentifier(v4.Address)),
	)
	if err != nil {
		return
	}
	s.transmit(req, reply, netip.Addr{})
}

// transmit crafts the reply frame per RFC 2131 §4.1 addressing rules and
// injects it into the switch.
func (s *dhcp4Server) transmit(req, reply *dhcpv4.DHCPv4, yiaddr netip.Addr) {
	v4 := s.gw.IPv4()
	dstMAC := net.HardwareAddr(req.ClientHWAddr)
	dstIP := broadcastIP4

	switch {
	case req.ClientIPAddr != nil && !req.ClientIPAddr.IsUnspecified():
		dstIP = req.ClientIPAddr
	case reply.MessageType() == dhcpv4.MessageTypeNak || req.IsBroadcast() || !yiaddr.IsValid():
		dstMAC = broadcastMAC
	default:
		dstIP = yiaddr.AsSlice()
	}

	frame := craftUDP4(s.gw.MAC(), dstMAC, v4.Address, dstIP,
		dhcp4ServerPort, dhcp4ClientPort, reply.ToBytes())
	s.gw.InjectFrame(frame)
}
