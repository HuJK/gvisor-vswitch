package gateway

import (
	"encoding/hex"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/insomniacslk/dhcp/dhcpv6"
	"github.com/insomniacslk/dhcp/iana"

	"github.com/HuJK/gvisor-vswitch/internal/switchcore"
)

const (
	dhcp6ServerPort = 547
	dhcp6ClientPort = 546
)

// DHCP6Config is the gateway-side stateful DHCPv6 (IA_NA) configuration.
type DHCP6Config struct {
	Enabled   bool
	PoolStart netip.Addr
	PoolEnd   netip.Addr
	LeaseTime time.Duration
	DNS       []net.IP
}

// dhcp6Server implements a minimal stateful DHCPv6 server (IA_NA only) at
// L2, sharing the binding/lease machinery with DHCPv4. The client is
// identified by its DUID (ClientID condition in static bindings).
type dhcp6Server struct {
	gw *Gateway

	mu      sync.Mutex
	cfg     DHCP6Config
	statics map[string]*StaticBinding

	leases *leaseTable
}

func newDHCP6Server(gw *Gateway) *dhcp6Server {
	s := &dhcp6Server{
		gw:      gw,
		statics: make(map[string]*StaticBinding),
		leases:  newLeaseTable(),
	}
	gw.AddFrameHandler(s.handleFrame)
	go s.sweepLoop()
	return s
}

func (s *dhcp6Server) sweepLoop() {
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

func (s *dhcp6Server) SetConfig(cfg DHCP6Config) error {
	if cfg.Enabled {
		v6 := s.gw.IPv6()
		if v6 == nil {
			return fmt.Errorf("gateway has no IPv6 network")
		}
		if !cfg.PoolStart.Is6() || cfg.PoolStart.Is4In6() || !cfg.PoolEnd.Is6() || cfg.PoolEnd.Is4In6() {
			return fmt.Errorf("dhcp6 pool must be IPv6 addresses")
		}
		if cfg.PoolEnd.Less(cfg.PoolStart) {
			return fmt.Errorf("pool_end is before pool_start")
		}
		network := gatewayNet6(v6)
		if !network.Contains(cfg.PoolStart) || !network.Contains(cfg.PoolEnd) {
			return fmt.Errorf("pool [%s, %s] is not inside the gateway network %s", cfg.PoolStart, cfg.PoolEnd, network)
		}
		if cfg.LeaseTime <= 0 {
			cfg.LeaseTime = defaultLeaseTime
		}
		if len(cfg.DNS) == 0 {
			cfg.DNS = []net.IP{v6.Address}
		}
	}
	s.mu.Lock()
	s.cfg = cfg
	s.mu.Unlock()
	return nil
}

func (s *dhcp6Server) Config() DHCP6Config {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.cfg
}

func gatewayNet6(v6 *V6Config) netip.Prefix {
	addr, _ := netip.AddrFromSlice(v6.Address.To16())
	return netip.PrefixFrom(addr, v6.PrefixLen).Masked()
}

func (s *dhcp6Server) PutStatic(b StaticBinding) error {
	if err := b.validate(); err != nil {
		return err
	}
	if !b.IP.Is6() || b.IP.Is4In6() {
		return fmt.Errorf("dhcp6 static binding ip must be IPv6")
	}
	s.mu.Lock()
	s.statics[b.ID] = &b
	s.mu.Unlock()
	return nil
}

// ReplaceStatics atomically replaces the entire static-binding set.
func (s *dhcp6Server) ReplaceStatics(bs []StaticBinding) error {
	m, err := buildStaticSet(bs, true)
	if err != nil {
		return err
	}
	s.mu.Lock()
	s.statics = m
	s.mu.Unlock()
	return nil
}

func (s *dhcp6Server) ListStatic() []StaticBinding {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]StaticBinding, 0, len(s.statics))
	for _, b := range s.statics {
		out = append(out, *b)
	}
	return out
}

func (s *dhcp6Server) DeleteStatic(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.statics[id]; !ok {
		return fmt.Errorf("static binding %q not found", id)
	}
	delete(s.statics, id)
	return nil
}

func (s *dhcp6Server) Leases() []Lease { return s.leases.snapshot() }

func (s *dhcp6Server) ReleaseLease(ip netip.Addr) error {
	if !s.leases.release(ip) {
		return fmt.Errorf("lease %s not found", ip)
	}
	return nil
}

func (s *dhcp6Server) PortDown(portID string) {
	s.leases.releaseByPort(portID)
}

func (s *dhcp6Server) serverDUID() dhcpv6.DUID {
	return &dhcpv6.DUIDLL{
		HWType:        iana.HWTypeEthernet,
		LinkLayerAddr: s.gw.MAC(),
	}
}

// handleFrame intercepts UDP :547 frames.
func (s *dhcp6Server) handleFrame(meta switchcore.Meta, frame []byte) bool {
	pkt, ok := parseIngress(frame)
	if !ok || !pkt.isUDP6 || pkt.dstPort != dhcp6ServerPort {
		return false
	}
	s.mu.Lock()
	cfg := s.cfg
	s.mu.Unlock()
	if !cfg.Enabled {
		return true
	}

	d, err := dhcpv6.FromBytes(pkt.payload)
	if err != nil {
		return true
	}
	msg, ok := d.(*dhcpv6.Message)
	if !ok {
		return true // relay messages unsupported
	}
	clientID := msg.Options.ClientID()
	if clientID == nil {
		return true
	}

	switch msg.MessageType {
	case dhcpv6.MessageTypeSolicit:
		s.replyAddress(meta, cfg, pkt, msg, true)
	case dhcpv6.MessageTypeRequest, dhcpv6.MessageTypeRenew, dhcpv6.MessageTypeRebind:
		s.replyAddress(meta, cfg, pkt, msg, false)
	case dhcpv6.MessageTypeRelease:
		duidHex := hex.EncodeToString(clientID.ToBytes())
		if l := s.leases.byClient(pkt.srcMAC.String(), duidHex); l != nil {
			s.leases.release(l.IP)
		}
		s.replyStatus(pkt, msg)
	case dhcpv6.MessageTypeInformationRequest:
		s.replyInformation(cfg, pkt, msg)
	}
	return true
}

// selectIP6 picks (and books) the client's address.
func (s *dhcp6Server) selectIP6(meta switchcore.Meta, cfg DHCP6Config, srcMAC net.HardwareAddr, duidHex string) netip.Addr {
	mac := srcMAC.String()
	v6 := s.gw.IPv6()
	gwIP, _ := netip.AddrFromSlice(v6.Address.To16())

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
		ClientID: duidHex,
		PortID:   meta.SrcPortID,
		Expiry:   time.Now().Add(cfg.LeaseTime),
	}

	if b := matchBinding(bindings, meta.SrcPortID, mac, duidHex); b != nil {
		if s.leases.inUse(b.IP, mac, duidHex) {
			return netip.Addr{}
		}
		lease.IP = b.IP
		lease.Static = true
		s.leases.set(lease)
		return b.IP
	}

	if cur := s.leases.byClient(mac, duidHex); cur != nil && !staticIPs[cur.IP] {
		lease.IP = cur.IP
		s.leases.set(lease)
		return cur.IP
	}

	return s.leases.allocate(cfg.PoolStart, cfg.PoolEnd, func(ip netip.Addr) bool {
		return ip == gwIP || staticIPs[ip]
	}, lease)
}

// replyAddress answers SOLICIT (advertise=true) and REQUEST/RENEW/REBIND.
func (s *dhcp6Server) replyAddress(meta switchcore.Meta, cfg DHCP6Config, pkt ingressPacket, msg *dhcpv6.Message, advertise bool) {
	duidHex := hex.EncodeToString(msg.Options.ClientID().ToBytes())
	ip := s.selectIP6(meta, cfg, pkt.srcMAC, duidHex)
	if !ip.IsValid() {
		return
	}

	iana := msg.Options.OneIANA()
	mods := []dhcpv6.Modifier{
		dhcpv6.WithServerID(s.serverDUID()),
		dhcpv6.WithDNS(cfg.DNS...),
	}
	if iana != nil {
		mods = append(mods, dhcpv6.WithIANA(dhcpv6.OptIAAddress{
			IPv6Addr:          ip.AsSlice(),
			PreferredLifetime: cfg.LeaseTime / 2,
			ValidLifetime:     cfg.LeaseTime,
		}))
	}

	var (
		reply *dhcpv6.Message
		err   error
	)
	if advertise {
		reply, err = dhcpv6.NewAdvertiseFromSolicit(msg, mods...)
	} else {
		reply, err = dhcpv6.NewReplyFromMessage(msg, mods...)
	}
	if err != nil {
		return
	}
	if iana != nil {
		// Preserve the client's IAID.
		if ia := reply.Options.OneIANA(); ia != nil {
			ia.IaId = iana.IaId
		}
	}
	s.transmit(pkt, reply)
}

func (s *dhcp6Server) replyStatus(pkt ingressPacket, msg *dhcpv6.Message) {
	reply, err := dhcpv6.NewReplyFromMessage(msg, dhcpv6.WithServerID(s.serverDUID()))
	if err != nil {
		return
	}
	s.transmit(pkt, reply)
}

func (s *dhcp6Server) replyInformation(cfg DHCP6Config, pkt ingressPacket, msg *dhcpv6.Message) {
	reply, err := dhcpv6.NewReplyFromMessage(msg,
		dhcpv6.WithServerID(s.serverDUID()),
		dhcpv6.WithDNS(cfg.DNS...),
	)
	if err != nil {
		return
	}
	s.transmit(pkt, reply)
}

// transmit unicasts the reply to the client's link-local address.
func (s *dhcp6Server) transmit(pkt ingressPacket, reply *dhcpv6.Message) {
	frame := craftUDP6(s.gw.MAC(), pkt.srcMAC, s.gw.LinkLocal(), pkt.srcIP,
		dhcp6ServerPort, dhcp6ClientPort, reply.ToBytes())
	s.gw.InjectFrame(frame)
}
