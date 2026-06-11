package manager

import (
	"fmt"
	"net"
	"time"

	"github.com/HuJK/gvisor-vswitch/internal/api"
	"github.com/HuJK/gvisor-vswitch/internal/switchcore"
)

// API vlan values map 1:1 onto switch-internal FDB keys (0 = untagged
// domain, 1-4094 = that VLAN).

func (m *Manager) DeleteFDBEntry(vlan int, mac string) error {
	hw, err := net.ParseMAC(mac)
	if err != nil {
		return fmt.Errorf("bad mac: %w", err)
	}
	return m.sw.DeleteFDBEntry(vlan, hw)
}

func (m *Manager) FlushFDB(req api.FDBFlushRequest) int {
	var vlan *int
	if req.VLAN != nil {
		v := *req.VLAN
		vlan = &v
	}
	return m.sw.FlushFDB(req.Port, vlan)
}

func (m *Manager) PutStaticFDB(req api.StaticFDBRequest) error {
	hw, err := net.ParseMAC(req.MAC)
	if err != nil {
		return fmt.Errorf("bad mac: %w", err)
	}
	return m.sw.AddStaticFDB(req.VLAN, hw, req.Port)
}

func (m *Manager) DeleteStaticFDB(vlan int, mac string) error {
	hw, err := net.ParseMAC(mac)
	if err != nil {
		return fmt.Errorf("bad mac: %w", err)
	}
	return m.sw.RemoveStaticFDB(vlan, hw)
}

func (m *Manager) GetFDBConfig() api.FDBConfig {
	return api.FDBConfig{AgingSeconds: int(m.sw.FDBMaxAge() / time.Second)}
}

func (m *Manager) SetFDBConfig(cfg api.FDBConfig) error {
	return m.sw.SetFDBMaxAge(time.Duration(cfg.AgingSeconds) * time.Second)
}

// SetSTP applies bridge-wide spanning-tree configuration.
func (m *Manager) SetSTP(req api.STPRequest) error {
	return m.sw.SetSTPConfig(switchcore.STPConfig{
		Enabled:      req.Enabled,
		Priority:     req.Priority,
		HelloTime:    time.Duration(req.HelloSeconds) * time.Second,
		MaxAge:       time.Duration(req.MaxAgeSeconds) * time.Second,
		ForwardDelay: time.Duration(req.ForwardDelaySeconds) * time.Second,
	})
}

// GetSTP returns the bridge status with per-port tree state.
func (m *Manager) GetSTP() api.STPResponse {
	st, ports := m.sw.STPStatus()
	return api.STPResponse{STPStatus: st, Ports: ports}
}
