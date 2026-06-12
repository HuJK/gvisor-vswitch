package manager

import (
	"fmt"
	"net"
	"net/netip"
	"sort"
	"time"

	"github.com/HuJK/gvisor-vswitch/internal/api"
	"github.com/HuJK/gvisor-vswitch/internal/gateway"
	"github.com/HuJK/gvisor-vswitch/internal/switchcore"
)

type gatewayRecord struct {
	req api.GatewayRequest
	gw  *gateway.Gateway
}

func gatewayPortID(vlan int) string {
	return fmt.Sprintf("gw-vlan%d", vlan)
}

// defaultGatewayMAC derives a stable locally-administered MAC per VLAN.
func defaultGatewayMAC(vlan int) net.HardwareAddr {
	return net.HardwareAddr{0x52, 0x54, 0x00, 0x67, byte(vlan >> 8), byte(vlan)}
}

// CreateGateway builds a gateway and attaches it to the switch as an access
// port on req.VLAN (0 = untagged domain).
func (m *Manager) CreateGateway(req api.GatewayRequest) (api.GatewayInfo, error) {
	if req.VLAN < 0 || req.VLAN > 4094 {
		return api.GatewayInfo{}, fmt.Errorf("vlan must be 0 (untagged domain) or 1-4094, got %d", req.VLAN)
	}

	m.mu.Lock()
	if _, dup := m.gateways[req.VLAN]; dup {
		m.mu.Unlock()
		return api.GatewayInfo{}, fmt.Errorf("gateway for vlan %d already exists", req.VLAN)
	}
	m.mu.Unlock()

	cfg := gateway.Config{
		PortID:                gatewayPortID(req.VLAN),
		MTU:                   uint32(req.MTU),
		EnableInternetRouting: req.EnableInternetRouting,
		EnableHostRouting:     req.EnableHostRouting,
		Allow:                 req.Allow,
		Deny:                  req.Deny,
		DNSProxy:              req.DNSProxy,
	}
	if req.MAC != "" {
		mac, err := net.ParseMAC(req.MAC)
		if err != nil {
			return api.GatewayInfo{}, fmt.Errorf("bad mac: %w", err)
		}
		cfg.MAC = mac
	} else {
		cfg.MAC = defaultGatewayMAC(req.VLAN)
	}
	if req.IPv4 != nil {
		ip := net.ParseIP(req.IPv4.Address)
		if ip == nil || ip.To4() == nil {
			return api.GatewayInfo{}, fmt.Errorf("bad ipv4 address %q", req.IPv4.Address)
		}
		if req.IPv4.PrefixLen < 1 || req.IPv4.PrefixLen > 30 {
			return api.GatewayInfo{}, fmt.Errorf("bad ipv4 prefix_len %d", req.IPv4.PrefixLen)
		}
		cfg.IPv4 = &gateway.V4Config{Address: ip.To4(), PrefixLen: req.IPv4.PrefixLen}
	}
	if req.IPv6 != nil {
		ip := net.ParseIP(req.IPv6.Address)
		if ip == nil || ip.To4() != nil {
			return api.GatewayInfo{}, fmt.Errorf("bad ipv6 address %q", req.IPv6.Address)
		}
		if req.IPv6.PrefixLen < 1 || req.IPv6.PrefixLen > 126 {
			return api.GatewayInfo{}, fmt.Errorf("bad ipv6 prefix_len %d", req.IPv6.PrefixLen)
		}
		cfg.IPv6 = &gateway.V6Config{Address: ip, PrefixLen: req.IPv6.PrefixLen}
		if req.IPv6.LinkLocal != "" {
			ll := net.ParseIP(req.IPv6.LinkLocal)
			if ll == nil {
				return api.GatewayInfo{}, fmt.Errorf("bad link_local %q", req.IPv6.LinkLocal)
			}
			cfg.IPv6.LinkLocal = ll
		}
	}

	gw, err := gateway.New(m.sw, cfg)
	if err != nil {
		return api.GatewayInfo{}, err
	}

	attrs := switchcore.PortAttrs{VLAN: req.VLAN, Isolated: req.Isolated}
	if err := m.sw.AddPort(gw, attrs); err != nil {
		gw.Close()
		return api.GatewayInfo{}, err
	}

	m.mu.Lock()
	if _, dup := m.gateways[req.VLAN]; dup {
		m.mu.Unlock()
		m.sw.RemovePort(cfg.PortID)
		return api.GatewayInfo{}, fmt.Errorf("gateway for vlan %d already exists", req.VLAN)
	}
	m.gateways[req.VLAN] = &gatewayRecord{req: req, gw: gw}
	m.mu.Unlock()

	return m.gatewayInfo(req.VLAN)
}

func (m *Manager) gateway(vlan int) (*gatewayRecord, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	rec, ok := m.gateways[vlan]
	if !ok {
		return nil, fmt.Errorf("gateway for vlan %d not found", vlan)
	}
	return rec, nil
}

func (m *Manager) gatewayInfo(vlan int) (api.GatewayInfo, error) {
	rec, err := m.gateway(vlan)
	if err != nil {
		return api.GatewayInfo{}, err
	}
	info := api.GatewayInfo{
		GatewayRequest: rec.req,
		MACEffective:   rec.gw.MAC().String(),
	}
	if rec.req.IPv6 != nil {
		info.LinkLocalEffective = rec.gw.LinkLocal().String()
	}
	if stats, ok := m.sw.PortStats(rec.gw.ID()); ok {
		info.Stats = stats
	}
	return info, nil
}

func (m *Manager) ListGateways() []api.GatewayInfo {
	m.mu.Lock()
	vlans := make([]int, 0, len(m.gateways))
	for v := range m.gateways {
		vlans = append(vlans, v)
	}
	m.mu.Unlock()
	out := make([]api.GatewayInfo, 0, len(vlans))
	for _, v := range vlans {
		if info, err := m.gatewayInfo(v); err == nil {
			out = append(out, info)
		}
	}
	return out
}

func (m *Manager) GetGateway(vlan int) (api.GatewayInfo, error) {
	return m.gatewayInfo(vlan)
}

func (m *Manager) DeleteGateway(vlan int) error {
	m.mu.Lock()
	rec, ok := m.gateways[vlan]
	if ok {
		delete(m.gateways, vlan)
	}
	m.mu.Unlock()
	if !ok {
		return fmt.Errorf("gateway for vlan %d not found", vlan)
	}
	m.sw.RemovePort(rec.gw.ID()) // closes the gateway
	return nil
}

func (m *Manager) AddForward(vlan int, req api.ForwardRequest) (api.ForwardInfo, error) {
	rec, err := m.gateway(vlan)
	if err != nil {
		return api.ForwardInfo{}, err
	}
	fr, err := rec.gw.AddForward(req.Type, req.Network, req.Bind, req.Host)
	if err != nil {
		return api.ForwardInfo{}, err
	}
	return forwardInfo(fr), nil
}

func (m *Manager) ListForwards(vlan int) ([]api.ForwardInfo, error) {
	rec, err := m.gateway(vlan)
	if err != nil {
		return nil, err
	}
	frs := rec.gw.ListForwards()
	out := make([]api.ForwardInfo, 0, len(frs))
	for _, fr := range frs {
		out = append(out, forwardInfo(fr))
	}
	return out, nil
}

func (m *Manager) DeleteForward(vlan int, id string) error {
	rec, err := m.gateway(vlan)
	if err != nil {
		return err
	}
	return rec.gw.DeleteForward(id)
}

// ReplaceForwards declaratively reconciles the gateway's forward set.
func (m *Manager) ReplaceForwards(vlan int, reqs []api.ForwardRequest) ([]api.ForwardInfo, error) {
	rec, err := m.gateway(vlan)
	if err != nil {
		return nil, err
	}
	specs := make([]gateway.ForwardSpec, 0, len(reqs))
	for _, r := range reqs {
		specs = append(specs, gateway.ForwardSpec{
			Type: r.Type, Network: r.Network, Bind: r.Bind, Host: r.Host,
		})
	}
	frs, err := rec.gw.ReplaceForwards(specs)
	out := make([]api.ForwardInfo, 0, len(frs))
	for _, fr := range frs {
		out = append(out, forwardInfo(fr))
	}
	return out, err
}

// ReplaceDHCPStatic atomically replaces a gateway's whole static-binding
// set for one address family.
func (m *Manager) ReplaceDHCPStatic(vlan, family int, bs []api.DHCPStaticBinding) error {
	rec, err := m.gateway(vlan)
	if err != nil {
		return err
	}
	gbs := make([]gateway.StaticBinding, 0, len(bs))
	for _, b := range bs {
		gb, err := staticToGateway(b)
		if err != nil {
			return fmt.Errorf("binding %q: %w", b.ID, err)
		}
		gbs = append(gbs, gb)
	}
	if family == 4 {
		return rec.gw.DHCP4().ReplaceStatics(gbs)
	}
	return rec.gw.DHCP6().ReplaceStatics(gbs)
}

func forwardInfo(fr gateway.ForwardRec) api.ForwardInfo {
	return api.ForwardInfo{
		ID: fr.ID,
		ForwardRequest: api.ForwardRequest{
			Type:    fr.Type,
			Network: fr.Network,
			Bind:    fr.Bind,
			Host:    fr.Host,
		},
	}
}

// --- DHCP ---

func (m *Manager) SetDHCP4(vlan int, cfg api.DHCP4Config) error {
	rec, err := m.gateway(vlan)
	if err != nil {
		return err
	}
	gcfg := gateway.DHCP4Config{
		Enabled:   cfg.Enabled,
		LeaseTime: time.Duration(cfg.LeaseSeconds) * time.Second,
	}
	if cfg.Enabled {
		if gcfg.PoolStart, err = netip.ParseAddr(cfg.PoolStart); err != nil {
			return fmt.Errorf("bad pool_start: %w", err)
		}
		if gcfg.PoolEnd, err = netip.ParseAddr(cfg.PoolEnd); err != nil {
			return fmt.Errorf("bad pool_end: %w", err)
		}
		for _, d := range cfg.DNS {
			ip := net.ParseIP(d)
			if ip == nil {
				return fmt.Errorf("bad dns address %q", d)
			}
			gcfg.DNS = append(gcfg.DNS, ip)
		}
	}
	return rec.gw.DHCP4().SetConfig(gcfg)
}

func (m *Manager) GetDHCP4(vlan int) (api.DHCP4Config, error) {
	rec, err := m.gateway(vlan)
	if err != nil {
		return api.DHCP4Config{}, err
	}
	gcfg := rec.gw.DHCP4().Config()
	cfg := api.DHCP4Config{
		Enabled:      gcfg.Enabled,
		LeaseSeconds: int(gcfg.LeaseTime / time.Second),
	}
	if gcfg.PoolStart.IsValid() {
		cfg.PoolStart = gcfg.PoolStart.String()
		cfg.PoolEnd = gcfg.PoolEnd.String()
	}
	for _, d := range gcfg.DNS {
		cfg.DNS = append(cfg.DNS, d.String())
	}
	return cfg, nil
}

func staticToGateway(b api.DHCPStaticBinding) (gateway.StaticBinding, error) {
	out := gateway.StaticBinding{
		ID:       b.ID,
		Order:    b.Order,
		PortID:   b.PortIdentifier,
		ClientID: b.ClientID,
	}
	if b.MAC != nil {
		mac, err := net.ParseMAC(*b.MAC)
		if err != nil {
			return out, fmt.Errorf("bad mac: %w", err)
		}
		s := mac.String()
		out.MAC = &s
	}
	ip, err := netip.ParseAddr(b.IP)
	if err != nil {
		return out, fmt.Errorf("bad ip: %w", err)
	}
	out.IP = ip
	return out, nil
}

func staticToAPI(b gateway.StaticBinding) api.DHCPStaticBinding {
	return api.DHCPStaticBinding{
		ID:             b.ID,
		Order:          b.Order,
		PortIdentifier: b.PortID,
		MAC:            b.MAC,
		ClientID:       b.ClientID,
		IP:             b.IP.String(),
	}
}

func (m *Manager) PutDHCPStatic(vlan, family int, b api.DHCPStaticBinding) error {
	rec, err := m.gateway(vlan)
	if err != nil {
		return err
	}
	gb, err := staticToGateway(b)
	if err != nil {
		return err
	}
	if family == 4 {
		return rec.gw.DHCP4().PutStatic(gb)
	}
	return rec.gw.DHCP6().PutStatic(gb)
}

func (m *Manager) ListDHCPStatic(vlan, family int) ([]api.DHCPStaticBinding, error) {
	rec, err := m.gateway(vlan)
	if err != nil {
		return nil, err
	}
	var gbs []gateway.StaticBinding
	if family == 4 {
		gbs = rec.gw.DHCP4().ListStatic()
	} else {
		gbs = rec.gw.DHCP6().ListStatic()
	}
	out := make([]api.DHCPStaticBinding, 0, len(gbs))
	for _, gb := range gbs {
		out = append(out, staticToAPI(gb))
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, nil
}

func (m *Manager) DeleteDHCPStatic(vlan, family int, id string) error {
	rec, err := m.gateway(vlan)
	if err != nil {
		return err
	}
	if family == 4 {
		return rec.gw.DHCP4().DeleteStatic(id)
	}
	return rec.gw.DHCP6().DeleteStatic(id)
}

func (m *Manager) ListDHCPLeases(vlan, family int) ([]api.LeaseInfo, error) {
	rec, err := m.gateway(vlan)
	if err != nil {
		return nil, err
	}
	var leases []gateway.Lease
	if family == 4 {
		leases = rec.gw.DHCP4().Leases()
	} else {
		leases = rec.gw.DHCP6().Leases()
	}
	out := make([]api.LeaseInfo, 0, len(leases))
	for _, l := range leases {
		out = append(out, api.LeaseInfo{
			IP:             l.IP.String(),
			MAC:            l.MAC,
			ClientID:       l.ClientID,
			PortIdentifier: l.PortID,
			ExpiresAt:      l.Expiry.UTC().Format(time.RFC3339),
			Static:         l.Static,
		})
	}
	return out, nil
}

func (m *Manager) DeleteDHCPLease(vlan, family int, ip string) error {
	rec, err := m.gateway(vlan)
	if err != nil {
		return err
	}
	addr, err := netip.ParseAddr(ip)
	if err != nil {
		return fmt.Errorf("bad ip: %w", err)
	}
	if family == 4 {
		return rec.gw.DHCP4().ReleaseLease(addr)
	}
	return rec.gw.DHCP6().ReleaseLease(addr)
}

func (m *Manager) SetDHCP6(vlan int, cfg api.DHCP6Config) error {
	rec, err := m.gateway(vlan)
	if err != nil {
		return err
	}
	gcfg := gateway.DHCP6Config{
		Enabled:   cfg.Enabled,
		LeaseTime: time.Duration(cfg.LeaseSeconds) * time.Second,
	}
	if cfg.Enabled {
		if gcfg.PoolStart, err = netip.ParseAddr(cfg.PoolStart); err != nil {
			return fmt.Errorf("bad pool_start: %w", err)
		}
		if gcfg.PoolEnd, err = netip.ParseAddr(cfg.PoolEnd); err != nil {
			return fmt.Errorf("bad pool_end: %w", err)
		}
		for _, d := range cfg.DNS {
			ip := net.ParseIP(d)
			if ip == nil {
				return fmt.Errorf("bad dns address %q", d)
			}
			gcfg.DNS = append(gcfg.DNS, ip)
		}
	}
	return rec.gw.DHCP6().SetConfig(gcfg)
}

func (m *Manager) GetDHCP6(vlan int) (api.DHCP6Config, error) {
	rec, err := m.gateway(vlan)
	if err != nil {
		return api.DHCP6Config{}, err
	}
	gcfg := rec.gw.DHCP6().Config()
	cfg := api.DHCP6Config{
		Enabled:      gcfg.Enabled,
		LeaseSeconds: int(gcfg.LeaseTime / time.Second),
	}
	if gcfg.PoolStart.IsValid() {
		cfg.PoolStart = gcfg.PoolStart.String()
		cfg.PoolEnd = gcfg.PoolEnd.String()
	}
	for _, d := range gcfg.DNS {
		cfg.DNS = append(cfg.DNS, d.String())
	}
	return cfg, nil
}

func (m *Manager) SetSLAAC(vlan int, cfg api.SLAACConfig) error {
	rec, err := m.gateway(vlan)
	if err != nil {
		return err
	}
	gcfg := gateway.SLAACConfig{
		Enabled:        cfg.Enabled,
		Interval:       time.Duration(cfg.IntervalSeconds) * time.Second,
		Managed:        cfg.Managed,
		Other:          cfg.Other,
		RouterLifetime: time.Duration(cfg.RouterLifetimeSeconds) * time.Second,
	}
	for _, p := range cfg.Prefixes {
		prefix, err := netip.ParsePrefix(p.Prefix)
		if err != nil {
			return fmt.Errorf("bad ra prefix %q: %w", p.Prefix, err)
		}
		gcfg.Prefixes = append(gcfg.Prefixes, gateway.RAPrefix{
			Prefix:            prefix,
			ValidLifetime:     time.Duration(p.ValidLifetime) * time.Second,
			PreferredLifetime: time.Duration(p.PreferredLifetime) * time.Second,
			OnLink:            p.OnLink,
			Autonomous:        p.Autonomous,
		})
	}
	return rec.gw.RA().SetConfig(gcfg)
}

func (m *Manager) GetSLAAC(vlan int) (api.SLAACConfig, error) {
	rec, err := m.gateway(vlan)
	if err != nil {
		return api.SLAACConfig{}, err
	}
	gcfg := rec.gw.RA().Config()
	cfg := api.SLAACConfig{
		Enabled:               gcfg.Enabled,
		IntervalSeconds:       int(gcfg.Interval / time.Second),
		Managed:               gcfg.Managed,
		Other:                 gcfg.Other,
		RouterLifetimeSeconds: int(gcfg.RouterLifetime / time.Second),
	}
	for _, p := range gcfg.Prefixes {
		cfg.Prefixes = append(cfg.Prefixes, api.RAPrefix{
			Prefix:            p.Prefix.String(),
			ValidLifetime:     int(p.ValidLifetime / time.Second),
			PreferredLifetime: int(p.PreferredLifetime / time.Second),
			OnLink:            p.OnLink,
			Autonomous:        p.Autonomous,
		})
	}
	return cfg, nil
}
