package manager

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/HuJK/gvisor-vswitch/internal/api"
)

// Config is the optional startup configuration: a declarative list of
// resources replayed through the same code paths as the REST API.
type Config struct {
	Ports    []api.PortRequest `json:"ports,omitempty"`
	Gateways []GatewayConfig   `json:"gateways,omitempty"`
}

// GatewayConfig is a gateway plus its sub-resources.
type GatewayConfig struct {
	api.GatewayRequest
	Forwards    []api.ForwardRequest    `json:"forwards,omitempty"`
	DHCP4       *api.DHCP4Config        `json:"dhcp4,omitempty"`
	DHCP4Static []api.DHCPStaticBinding `json:"dhcp4_static,omitempty"`
	DHCP6       *api.DHCP6Config        `json:"dhcp6,omitempty"`
	DHCP6Static []api.DHCPStaticBinding `json:"dhcp6_static,omitempty"`
	SLAAC       *api.SLAACConfig        `json:"slaac,omitempty"`
}

// ReplayConfig applies a JSON config file at startup.
func (m *Manager) ReplayConfig(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	var cfg Config
	if err := json.Unmarshal(data, &cfg); err != nil {
		return fmt.Errorf("parse config: %w", err)
	}

	for _, gw := range cfg.Gateways {
		if _, err := m.CreateGateway(gw.GatewayRequest); err != nil {
			return fmt.Errorf("gateway vlan %d: %w", gw.VLAN, err)
		}
		for _, fwd := range gw.Forwards {
			if _, err := m.AddForward(gw.VLAN, fwd); err != nil {
				return fmt.Errorf("gateway vlan %d forward %s %s: %w", gw.VLAN, fwd.Type, fwd.Bind, err)
			}
		}
		if gw.DHCP4 != nil {
			if err := m.SetDHCP4(gw.VLAN, *gw.DHCP4); err != nil {
				return fmt.Errorf("gateway vlan %d dhcp4: %w", gw.VLAN, err)
			}
		}
		for _, b := range gw.DHCP4Static {
			if err := m.PutDHCPStatic(gw.VLAN, 4, b); err != nil {
				return fmt.Errorf("gateway vlan %d dhcp4 static %q: %w", gw.VLAN, b.ID, err)
			}
		}
		if gw.DHCP6 != nil {
			if err := m.SetDHCP6(gw.VLAN, *gw.DHCP6); err != nil {
				return fmt.Errorf("gateway vlan %d dhcp6: %w", gw.VLAN, err)
			}
		}
		for _, b := range gw.DHCP6Static {
			if err := m.PutDHCPStatic(gw.VLAN, 6, b); err != nil {
				return fmt.Errorf("gateway vlan %d dhcp6 static %q: %w", gw.VLAN, b.ID, err)
			}
		}
		if gw.SLAAC != nil {
			if err := m.SetSLAAC(gw.VLAN, *gw.SLAAC); err != nil {
				return fmt.Errorf("gateway vlan %d slaac: %w", gw.VLAN, err)
			}
		}
	}

	for _, p := range cfg.Ports {
		if _, err := m.CreatePort(p); err != nil {
			return fmt.Errorf("port %q: %w", p.Identifier, err)
		}
	}
	return nil
}
