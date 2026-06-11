package manager_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/HuJK/gvisor-vswitch/internal/manager"
)

func TestReplayConfig(t *testing.T) {
	dir := t.TempDir()
	sock := filepath.Join(dir, "vm1.sock")
	cfgPath := filepath.Join(dir, "config.json")

	cfg := `{
  "gateways": [{
    "vlan": 100,
    "ipv4": {"address": "10.0.100.2", "prefix_len": 24},
    "forwards": [{"type": "remote", "network": "tcp", "bind": "10.0.100.2:25", "host": "127.0.0.1:1025"}],
    "dhcp4": {"enabled": true, "pool_start": "10.0.100.100", "pool_end": "10.0.100.199"},
    "dhcp4_static": [{"id": "web1", "mac": "52:54:00:00:00:01", "ip": "10.0.100.10"}],
    "slaac": {"enabled": false}
  }],
  "ports": [
    {"identifier": "vm1", "vlan": 100, "mode": "server", "transport": "unix", "local": "` + sock + `"}
  ]
}`
	if err := os.WriteFile(cfgPath, []byte(cfg), 0644); err != nil {
		t.Fatal(err)
	}

	m := manager.New()
	t.Cleanup(m.Close)
	if err := m.ReplayConfig(cfgPath); err != nil {
		t.Fatalf("ReplayConfig: %v", err)
	}

	if got := len(m.ListGateways()); got != 1 {
		t.Errorf("gateways = %d, want 1", got)
	}
	if got := len(m.ListPorts()); got != 1 {
		t.Errorf("ports = %d, want 1", got)
	}
	fwds, err := m.ListForwards(100)
	if err != nil || len(fwds) != 1 {
		t.Errorf("forwards = %v, %v", fwds, err)
	}
	dhcp, err := m.GetDHCP4(100)
	if err != nil || !dhcp.Enabled || dhcp.PoolStart != "10.0.100.100" {
		t.Errorf("dhcp4 = %+v, %v", dhcp, err)
	}
	statics, err := m.ListDHCPStatic(100, 4)
	if err != nil || len(statics) != 1 || statics[0].ID != "web1" {
		t.Errorf("statics = %v, %v", statics, err)
	}

	// Errors carry context.
	bad := filepath.Join(dir, "bad.json")
	os.WriteFile(bad, []byte(`{"ports":[{"identifier":"x/y","mode":"server","transport":"unix","local":"`+sock+`2"}]}`), 0644)
	m2 := manager.New()
	t.Cleanup(m2.Close)
	if err := m2.ReplayConfig(bad); err == nil {
		t.Error("bad config accepted")
	}
}
