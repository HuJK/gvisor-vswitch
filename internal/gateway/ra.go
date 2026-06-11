package gateway

import (
	"encoding/binary"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"time"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"

	"github.com/HuJK/gvisor-vswitch/internal/switchcore"
)

const (
	defaultRAInterval        = 200 * time.Second
	defaultRouterLifetime    = 1800 * time.Second
	defaultValidLifetime     = 30 * 24 * time.Hour
	defaultPreferredLifetime = 7 * 24 * time.Hour
)

var (
	allNodesIP6 = net.ParseIP("ff02::1")
	allNodesMAC = net.HardwareAddr{0x33, 0x33, 0x00, 0x00, 0x00, 0x01}
)

// RAPrefix is one Prefix Information option.
type RAPrefix struct {
	Prefix            netip.Prefix
	ValidLifetime     time.Duration
	PreferredLifetime time.Duration
	OnLink            bool
	Autonomous        bool
}

// SLAACConfig configures the router-advertisement service.
type SLAACConfig struct {
	Enabled        bool
	Interval       time.Duration
	Managed        bool // M flag: addresses via DHCPv6
	Other          bool // O flag: other config via DHCPv6
	RouterLifetime time.Duration
	Prefixes       []RAPrefix
}

// raServer broadcasts periodic RAs and answers router solicitations at L2.
type raServer struct {
	gw *Gateway

	mu   sync.Mutex
	cfg  SLAACConfig
	kick chan struct{} // wakes the loop after config changes
}

func newRAServer(gw *Gateway) *raServer {
	s := &raServer{gw: gw, kick: make(chan struct{}, 1)}
	gw.AddFrameHandler(s.handleFrame)
	go s.loop()
	return s
}

// SetConfig validates and applies the RA configuration.
func (s *raServer) SetConfig(cfg SLAACConfig) error {
	if cfg.Enabled {
		if s.gw.IPv6() == nil {
			return fmt.Errorf("gateway has no IPv6 network")
		}
		if cfg.Interval <= 0 {
			cfg.Interval = defaultRAInterval
		}
		if cfg.RouterLifetime <= 0 {
			cfg.RouterLifetime = defaultRouterLifetime
		}
		for i := range cfg.Prefixes {
			p := &cfg.Prefixes[i]
			if !p.Prefix.Addr().Is6() || p.Prefix.Addr().Is4In6() {
				return fmt.Errorf("ra prefix %s is not IPv6", p.Prefix)
			}
			if p.ValidLifetime <= 0 {
				p.ValidLifetime = defaultValidLifetime
			}
			if p.PreferredLifetime <= 0 {
				p.PreferredLifetime = defaultPreferredLifetime
			}
		}
	}
	s.mu.Lock()
	s.cfg = cfg
	s.mu.Unlock()
	select {
	case s.kick <- struct{}{}:
	default:
	}
	return nil
}

func (s *raServer) Config() SLAACConfig {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.cfg
}

func (s *raServer) loop() {
	timer := time.NewTimer(time.Hour)
	defer timer.Stop()
	for {
		s.mu.Lock()
		cfg := s.cfg
		s.mu.Unlock()

		if cfg.Enabled {
			s.send(cfg, allNodesMAC, allNodesIP6)
			timer.Reset(cfg.Interval)
		} else {
			timer.Reset(time.Hour)
		}

		select {
		case <-s.gw.Context().Done():
			return
		case <-s.kick:
		case <-timer.C:
		}
	}
}

// handleFrame answers router solicitations (ICMPv6 type 133).
func (s *raServer) handleFrame(_ switchcore.Meta, frame []byte) bool {
	pkt, ok := parseIngress(frame)
	if !ok || !pkt.isICMP6 || pkt.icmpTyp != uint8(header.ICMPv6RouterSolicit) {
		return false
	}
	s.mu.Lock()
	cfg := s.cfg
	s.mu.Unlock()
	if !cfg.Enabled {
		return true // consume; nobody else will answer
	}

	dstMAC, dstIP := allNodesMAC, allNodesIP6
	if !pkt.srcIP.IsUnspecified() {
		dstMAC, dstIP = pkt.srcMAC, pkt.srcIP
	}
	s.send(cfg, dstMAC, dstIP)
	return true
}

// send crafts and injects one RA.
func (s *raServer) send(cfg SLAACConfig, dstMAC net.HardwareAddr, dstIP net.IP) {
	opts := header.NDPOptionsSerializer{
		header.NDPSourceLinkLayerAddressOption(tcpip.LinkAddress(s.gw.MAC())),
	}
	for _, p := range cfg.Prefixes {
		opts = append(opts, buildPrefixInfo(p))
	}

	body := make([]byte, header.ICMPv6HeaderSize+header.NDPRAMinimumSize+opts.Length())
	icmp := header.ICMPv6(body)
	icmp.SetType(header.ICMPv6RouterAdvert)

	ra := body[header.ICMPv6HeaderSize:]
	ra[0] = 64 // current hop limit suggestion
	if cfg.Managed {
		ra[1] |= 1 << 7
	}
	if cfg.Other {
		ra[1] |= 1 << 6
	}
	binary.BigEndian.PutUint16(ra[2:4], uint16(cfg.RouterLifetime/time.Second))
	// Reachable time and retrans timer: 0 = unspecified.
	header.NDPOptions(ra[header.NDPRAMinimumSize:]).Serialize(opts)

	frame := craftICMP6(s.gw.MAC(), dstMAC, s.gw.LinkLocal(), dstIP, body, header.NDPHopLimit)
	s.gw.InjectFrame(frame)
}

// buildPrefixInfo fills the 30-byte Prefix Information option body
// (RFC 4861 §4.6.2, excluding the type/length bytes).
func buildPrefixInfo(p RAPrefix) header.NDPPrefixInformation {
	b := make([]byte, 30)
	b[0] = uint8(p.Prefix.Bits())
	if p.OnLink {
		b[1] |= 1 << 7
	}
	if p.Autonomous {
		b[1] |= 1 << 6
	}
	binary.BigEndian.PutUint32(b[2:6], uint32(p.ValidLifetime/time.Second))
	binary.BigEndian.PutUint32(b[6:10], uint32(p.PreferredLifetime/time.Second))
	addr := p.Prefix.Addr().As16()
	copy(b[14:30], addr[:])
	return header.NDPPrefixInformation(b)
}
