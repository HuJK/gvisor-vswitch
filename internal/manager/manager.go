// Package manager owns the live objects of one gvswitch instance: the L2
// switch, the API-created ports, and (per VLAN) the gateways. The REST
// handlers in internal/api call into it.
package manager

import (
	"fmt"
	"sync"

	"github.com/HuJK/gvisor-vswitch/internal/api"
	"github.com/HuJK/gvisor-vswitch/internal/ports"
	"github.com/HuJK/gvisor-vswitch/internal/switchcore"
)

// Manager is safe for concurrent use.
type Manager struct {
	sw *switchcore.Switch

	mu       sync.Mutex
	ports    map[string]*portRecord
	gateways map[int]*gatewayRecord
}

type portRecord struct {
	req  api.PortRequest
	port ports.ManagedPort
}

func New() *Manager {
	m := &Manager{
		sw:       switchcore.New(),
		ports:    make(map[string]*portRecord),
		gateways: make(map[int]*gatewayRecord),
	}
	// When a switchport goes offline: release its DHCP leases, and unless
	// the port opted out, remove it entirely (peer closing the socket /
	// the tap or af_xdp interface vanishing reclaims the port without a
	// DELETE call).
	m.sw.OnPortDown(func(portID string) {
		m.mu.Lock()
		gws := make([]*gatewayRecord, 0, len(m.gateways))
		for _, rec := range m.gateways {
			gws = append(gws, rec)
		}
		rec, isPort := m.ports[portID]
		autoRemove := isPort && (rec.req.AutoRemove == nil || *rec.req.AutoRemove)
		var port ports.ManagedPort
		if isPort {
			port = rec.port
		}
		m.mu.Unlock()

		for _, gw := range gws {
			gw.gw.PortDown(portID)
		}
		if autoRemove && !port.Status().Online {
			go m.DeletePort(portID)
		}
	})
	return m
}

// Switch exposes the underlying switch (gateways attach to it).
func (m *Manager) Switch() *switchcore.Switch { return m.sw }

// Close tears everything down.
func (m *Manager) Close() {
	m.sw.Close()
}

// CreatePort validates req, builds the transport and registers the port.
func (m *Manager) CreatePort(req api.PortRequest) (api.PortInfo, error) {
	if err := api.ValidateIdentifier(req.Identifier); err != nil {
		return api.PortInfo{}, err
	}
	attrs, err := req.Attrs()
	if err != nil {
		return api.PortInfo{}, err
	}

	m.mu.Lock()
	if _, dup := m.ports[req.Identifier]; dup {
		m.mu.Unlock()
		return api.PortInfo{}, fmt.Errorf("port %q already exists", req.Identifier)
	}
	m.mu.Unlock()

	var port ports.ManagedPort
	if req.Transport == "vhost-user" {
		path := req.Local
		if req.Mode == "client" {
			path = req.Remote
		}
		port, err = ports.NewVhostUser(m.sw, ports.VhostUserConfig{
			ID:            req.Identifier,
			Mode:          req.Mode,
			Path:          path,
			ReplacingMode: ports.ReplacingMode(req.ReplacingMode),
		})
		if err != nil {
			return api.PortInfo{}, err
		}
		if err := m.sw.AddPort(port, attrs); err != nil {
			port.Close()
			return api.PortInfo{}, err
		}
		m.mu.Lock()
		m.ports[req.Identifier] = &portRecord{req: req, port: port}
		m.mu.Unlock()
		return m.portInfoLocked(req.Identifier)
	}
	switch req.Mode {
	case "client":
		switch req.Transport {
		case "tap", "tapbr":
			port, err = ports.NewTap(m.sw, ports.TapConfig{
				ID:      req.Identifier,
				TapName: req.TapName,
				Bridge:  req.Bridge,
				AddToBr: req.Transport == "tapbr",
			})
		case "af_xdp":
			port, err = ports.NewAFXDP(m.sw, ports.AFXDPConfig{
				ID:        req.Identifier,
				Interface: req.Interface,
				QueueID:   req.QueueID,
			})
		default:
			port, err = ports.NewClient(m.sw, ports.ClientConfig{
				ID:        req.Identifier,
				Transport: req.Transport,
				Local:     req.Local,
				Remote:    req.Remote,
			})
		}
	case "server":
		port, err = ports.NewServer(m.sw, ports.ServerConfig{
			ID:        req.Identifier,
			Transport: req.Transport,
			Listen:    req.Local,
			Mode:      ports.ReplacingMode(req.ReplacingMode),
			Attrs:     attrs,
		})
	default:
		err = fmt.Errorf("mode must be \"client\" or \"server\", got %q", req.Mode)
	}
	if err != nil {
		return api.PortInfo{}, err
	}

	if err := m.sw.AddPort(port, attrs); err != nil {
		port.Close()
		return api.PortInfo{}, err
	}

	m.mu.Lock()
	m.ports[req.Identifier] = &portRecord{req: req, port: port}
	m.mu.Unlock()

	return m.portInfoLocked(req.Identifier)
}

// GetPort returns one port.
func (m *Manager) GetPort(id string) (api.PortInfo, error) {
	return m.portInfoLocked(id)
}

// ListPorts returns all API-created ports.
func (m *Manager) ListPorts() []api.PortInfo {
	m.mu.Lock()
	ids := make([]string, 0, len(m.ports))
	for id := range m.ports {
		ids = append(ids, id)
	}
	m.mu.Unlock()

	out := make([]api.PortInfo, 0, len(ids))
	for _, id := range ids {
		if info, err := m.portInfoLocked(id); err == nil {
			out = append(out, info)
		}
	}
	return out
}

// PatchPort updates policy attributes of a port (and its multiplex
// subports).
func (m *Manager) PatchPort(id string, patch api.PortPatch) (api.PortInfo, error) {
	m.mu.Lock()
	rec, ok := m.ports[id]
	m.mu.Unlock()
	if !ok {
		return api.PortInfo{}, fmt.Errorf("port %q not found", id)
	}

	attrs, ok := m.sw.PortAttrs(id)
	if !ok {
		return api.PortInfo{}, fmt.Errorf("port %q not registered", id)
	}
	attrs, err := patch.Apply(attrs)
	if err != nil {
		return api.PortInfo{}, err
	}
	if err := m.sw.UpdatePortAttrs(id, attrs); err != nil {
		return api.PortInfo{}, err
	}
	if u, ok := rec.port.(ports.SubAttrsUpdater); ok {
		u.UpdateSubAttrs(attrs)
	}

	// Reflect the change in the stored request for GET.
	m.mu.Lock()
	v := attrs.VLAN
	rec.req.VLAN = &v
	rec.req.Isolated = attrs.Isolated
	if attrs.SecurityMAC == nil {
		rec.req.PortSecurity = nil
	} else {
		s := attrs.SecurityMAC.String()
		rec.req.PortSecurity = &s
	}
	m.mu.Unlock()

	return m.portInfoLocked(id)
}

// DeletePort removes a port and closes its transport.
func (m *Manager) DeletePort(id string) error {
	m.mu.Lock()
	_, ok := m.ports[id]
	if ok {
		delete(m.ports, id)
	}
	m.mu.Unlock()
	if !ok {
		return fmt.Errorf("port %q not found", id)
	}
	m.sw.RemovePort(id)
	return nil
}

// FDB snapshots the forwarding database.
func (m *Manager) FDB() []api.FDBRow {
	entries := m.sw.FDB()
	out := make([]api.FDBRow, 0, len(entries))
	for _, e := range entries {
		out = append(out, api.FDBRow{
			VLAN:       int(e.VLAN),
			MAC:        e.MAC,
			Port:       e.PortID,
			AgeSeconds: int(e.Age.Seconds()),
			Static:     e.Static,
		})
	}
	return out
}

func (m *Manager) portInfoLocked(id string) (api.PortInfo, error) {
	m.mu.Lock()
	rec, ok := m.ports[id]
	m.mu.Unlock()
	if !ok {
		return api.PortInfo{}, fmt.Errorf("port %q not found", id)
	}
	st := rec.port.Status()
	req := rec.req
	info := api.PortInfo{
		Identifier:    req.Identifier,
		VLAN:          switchcore.VLANTrunk,
		Isolated:      req.Isolated,
		PortSecurity:  req.PortSecurity,
		Enabled:       true,
		AutoRemove:    req.AutoRemove == nil || *req.AutoRemove,
		Mode:          req.Mode,
		Transport:     req.Transport,
		Local:         req.Local,
		Remote:        req.Remote,
		ReplacingMode: req.ReplacingMode,
		TapName:       req.TapName,
		Bridge:        req.Bridge,
		Interface:     req.Interface,
		QueueID:       req.QueueID,
		Online:        st.Online,
		Peer:          st.Peer,
		Connections:   st.Connections,
	}
	if attrs, ok := m.sw.PortAttrs(id); ok {
		info.Enabled = !attrs.Disabled
		info.VLAN = attrs.VLAN
	}
	if stats, ok := m.sw.PortStats(id); ok {
		info.Stats = stats
	}
	return info, nil
}
