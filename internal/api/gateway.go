package api

import (
	"fmt"
	"net/http"
	"strconv"

	"github.com/HuJK/gvisor-vswitch/internal/switchcore"
)

// Gateways are addressed by the VLAN they serve: 0 = the untagged domain,
// 1-4094 = that access VLAN. (Trunk gateways make no sense: the gateway is
// always an access-style port.)

// GatewayRequest creates a per-VLAN gateway.
type GatewayRequest struct {
	VLAN     int    `json:"vlan"`
	MAC      string `json:"mac,omitempty"` // default: derived from VLAN
	Isolated bool   `json:"isolated,omitempty"`
	MTU      int    `json:"mtu,omitempty"` // default 1500

	IPv4 *GatewayV4 `json:"ipv4,omitempty"`
	IPv6 *GatewayV6 `json:"ipv6,omitempty"`

	// Routing policy (slirpnetstack semantics).
	EnableInternetRouting bool     `json:"enable_internet_routing,omitempty"`
	EnableHostRouting     bool     `json:"enable_host_routing,omitempty"`
	Allow                 []string `json:"allow,omitempty"` // ip/cidr[:portmin-portmax]
	Deny                  []string `json:"deny,omitempty"`

	// DNSProxy: answer DNS on the gateway's own :53 by resolving through
	// the host system's resolver (Android: DnsResolver via dnsproxyd, so
	// Private DNS/VPN DNS apply; elsewhere: /etc/resolv.conf upstreams).
	DNSProxy bool `json:"dns_proxy,omitempty"`
}

// GatewayV4 is the gateway's IPv4 side: it owns Address/PrefixLen and NATs
// guest traffic to the host.
type GatewayV4 struct {
	Address   string `json:"address"`
	PrefixLen int    `json:"prefix_len"`
}

// GatewayV6 is the IPv6 side, with an optional explicit link-local address
// (default: EUI-64 from the gateway MAC).
type GatewayV6 struct {
	Address   string `json:"address"`
	PrefixLen int    `json:"prefix_len"`
	LinkLocal string `json:"link_local,omitempty"`
}

// GatewayInfo is the GET representation.
type GatewayInfo struct {
	GatewayRequest
	MACEffective       string               `json:"mac_effective"`
	LinkLocalEffective string               `json:"link_local_effective,omitempty"`
	Stats              switchcore.PortStats `json:"stats"`
}

// ForwardRequest adds a port forward to a gateway.
//   - local:  bind on the host, forward into the guest network
//   - remote: guest connects to gateway bind ip:port, forwarded to a host
//     address
type ForwardRequest struct {
	Type    string `json:"type"`    // local | remote
	Network string `json:"network"` // tcp | udp
	Bind    string `json:"bind"`    // ip:port
	Host    string `json:"host"`    // ip:port (DNS labels allowed)
}

// ForwardInfo describes an installed forward.
type ForwardInfo struct {
	ID string `json:"id"`
	ForwardRequest
}

// DHCP4Config configures the gateway's DHCPv4 server. The pool must lie
// inside the gateway network; the gateway IP and static-binding IPs are
// skipped automatically.
type DHCP4Config struct {
	Enabled      bool     `json:"enabled"`
	PoolStart    string   `json:"pool_start,omitempty"`
	PoolEnd      string   `json:"pool_end,omitempty"`
	LeaseSeconds int      `json:"lease_seconds,omitempty"` // default 3600
	DNS          []string `json:"dns,omitempty"`           // default: gateway IP
}

// DHCP6Config configures stateful DHCPv6 (IA_NA).
type DHCP6Config struct {
	Enabled      bool     `json:"enabled"`
	PoolStart    string   `json:"pool_start,omitempty"`
	PoolEnd      string   `json:"pool_end,omitempty"`
	LeaseSeconds int      `json:"lease_seconds,omitempty"`
	DNS          []string `json:"dns,omitempty"`
}

// DHCPStaticBinding pins an IP to a client. Conditions are AND-ed: nil
// means wildcard, any non-wildcard mismatch disqualifies the binding. Among
// matching bindings the one with the most matched conditions wins, then the
// higher Order.
type DHCPStaticBinding struct {
	ID    string `json:"id"`
	Order int    `json:"order,omitempty"`
	// Conditions (at least one must be set):
	PortIdentifier *string `json:"port_identifier,omitempty"`
	MAC            *string `json:"mac,omitempty"`
	ClientID       *string `json:"client_id,omitempty"` // DHCPv4: option 61 (hex); DHCPv6: DUID (hex)
	IP             string  `json:"ip"`
}

// LeaseInfo is one active lease.
type LeaseInfo struct {
	IP             string `json:"ip"`
	MAC            string `json:"mac,omitempty"`
	ClientID       string `json:"client_id,omitempty"`
	PortIdentifier string `json:"port_identifier,omitempty"`
	ExpiresAt      string `json:"expires_at"` // RFC3339
	Static         bool   `json:"static"`
}

// RAPrefix is one Prefix Information option in router advertisements.
type RAPrefix struct {
	Prefix            string `json:"prefix"`                       // cidr
	ValidLifetime     int    `json:"valid_lifetime,omitempty"`     // seconds, default 2592000
	PreferredLifetime int    `json:"preferred_lifetime,omitempty"` // seconds, default 604800
	OnLink            bool   `json:"on_link"`
	Autonomous        bool   `json:"autonomous"`
}

// SLAACConfig configures router advertisements.
type SLAACConfig struct {
	Enabled               bool       `json:"enabled"`
	IntervalSeconds       int        `json:"interval_seconds,omitempty"` // default 200
	Managed               bool       `json:"managed"`
	Other                 bool       `json:"other"`
	RouterLifetimeSeconds int        `json:"router_lifetime_seconds,omitempty"` // default 1800
	Prefixes              []RAPrefix `json:"prefixes,omitempty"`
}

// STPRequest configures the bridge-wide spanning tree.
type STPRequest struct {
	Enabled             bool   `json:"enabled"`
	Priority            uint16 `json:"priority,omitempty"`              // default 32768
	HelloSeconds        int    `json:"hello_seconds,omitempty"`         // default 2
	MaxAgeSeconds       int    `json:"max_age_seconds,omitempty"`       // default 20
	ForwardDelaySeconds int    `json:"forward_delay_seconds,omitempty"` // default 15
}

// STPResponse is the bridge status plus per-port tree state.
type STPResponse struct {
	switchcore.STPStatus
	Ports map[string]switchcore.STPPortStatus `json:"ports"`
}

// GatewayBackend is the gateway half of the API surface.
type GatewayBackend interface {
	CreateGateway(req GatewayRequest) (GatewayInfo, error)
	ListGateways() []GatewayInfo
	GetGateway(vlan int) (GatewayInfo, error)
	DeleteGateway(vlan int) error

	AddForward(vlan int, req ForwardRequest) (ForwardInfo, error)
	ListForwards(vlan int) ([]ForwardInfo, error)
	DeleteForward(vlan int, id string) error
	ReplaceForwards(vlan int, reqs []ForwardRequest) ([]ForwardInfo, error)

	SetDHCP4(vlan int, cfg DHCP4Config) error
	GetDHCP4(vlan int) (DHCP4Config, error)
	PutDHCPStatic(vlan int, family int, b DHCPStaticBinding) error
	ReplaceDHCPStatic(vlan int, family int, bs []DHCPStaticBinding) error
	ListDHCPStatic(vlan int, family int) ([]DHCPStaticBinding, error)
	DeleteDHCPStatic(vlan int, family int, id string) error
	ListDHCPLeases(vlan int, family int) ([]LeaseInfo, error)
	DeleteDHCPLease(vlan int, family int, ip string) error
	SetDHCP6(vlan int, cfg DHCP6Config) error
	GetDHCP6(vlan int) (DHCP6Config, error)

	SetSLAAC(vlan int, cfg SLAACConfig) error
	GetSLAAC(vlan int) (SLAACConfig, error)
}

func registerGatewayRoutes(mux *http.ServeMux, h *handlers) {
	mux.HandleFunc("POST /api/v1/gateways", h.createGateway)
	mux.HandleFunc("GET /api/v1/gateways", h.listGateways)
	mux.HandleFunc("GET /api/v1/gateways/{vlan}", h.gw(h.getGateway))
	mux.HandleFunc("DELETE /api/v1/gateways/{vlan}", h.gw(h.deleteGateway))

	mux.HandleFunc("POST /api/v1/gateways/{vlan}/forwards", h.gw(h.addForward))
	mux.HandleFunc("PUT /api/v1/gateways/{vlan}/forwards", h.gw(h.replaceForwards))
	mux.HandleFunc("GET /api/v1/gateways/{vlan}/forwards", h.gw(h.listForwards))
	mux.HandleFunc("DELETE /api/v1/gateways/{vlan}/forwards/{id}", h.gw(h.deleteForward))

	for family, name := range map[int]string{4: "dhcp4", 6: "dhcp6"} {
		family := family
		mux.HandleFunc("PUT /api/v1/gateways/{vlan}/"+name, h.gw(func(w http.ResponseWriter, r *http.Request, vlan int) {
			h.setDHCP(w, r, vlan, family)
		}))
		mux.HandleFunc("GET /api/v1/gateways/{vlan}/"+name, h.gw(func(w http.ResponseWriter, r *http.Request, vlan int) {
			h.getDHCP(w, r, vlan, family)
		}))
		mux.HandleFunc("PUT /api/v1/gateways/{vlan}/"+name+"/static/{id}", h.gw(func(w http.ResponseWriter, r *http.Request, vlan int) {
			h.putDHCPStatic(w, r, vlan, family)
		}))
		mux.HandleFunc("PUT /api/v1/gateways/{vlan}/"+name+"/static", h.gw(func(w http.ResponseWriter, r *http.Request, vlan int) {
			h.replaceDHCPStatic(w, r, vlan, family)
		}))
		mux.HandleFunc("GET /api/v1/gateways/{vlan}/"+name+"/static", h.gw(func(w http.ResponseWriter, r *http.Request, vlan int) {
			h.listDHCPStatic(w, r, vlan, family)
		}))
		mux.HandleFunc("DELETE /api/v1/gateways/{vlan}/"+name+"/static/{id}", h.gw(func(w http.ResponseWriter, r *http.Request, vlan int) {
			h.deleteDHCPStatic(w, r, vlan, family)
		}))
		mux.HandleFunc("GET /api/v1/gateways/{vlan}/"+name+"/leases", h.gw(func(w http.ResponseWriter, r *http.Request, vlan int) {
			h.listDHCPLeases(w, r, vlan, family)
		}))
		mux.HandleFunc("DELETE /api/v1/gateways/{vlan}/"+name+"/leases/{ip}", h.gw(func(w http.ResponseWriter, r *http.Request, vlan int) {
			h.deleteDHCPLease(w, r, vlan, family)
		}))
	}

	mux.HandleFunc("PUT /api/v1/gateways/{vlan}/slaac", h.gw(h.setSLAAC))
	mux.HandleFunc("GET /api/v1/gateways/{vlan}/slaac", h.gw(h.getSLAAC))
}

// gw parses the {vlan} path parameter.
func (h *handlers) gw(fn func(w http.ResponseWriter, r *http.Request, vlan int)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		vlan, err := strconv.Atoi(r.PathValue("vlan"))
		if err != nil || vlan < 0 || vlan > 4094 {
			writeErr(w, http.StatusBadRequest, fmt.Errorf("bad vlan %q (0 = untagged domain, 1-4094 = access vlan)", r.PathValue("vlan")))
			return
		}
		fn(w, r, vlan)
	}
}

func (h *handlers) createGateway(w http.ResponseWriter, r *http.Request) {
	var req GatewayRequest
	if !decodeBody(w, r, &req) {
		return
	}
	info, err := h.b.CreateGateway(req)
	if err != nil {
		writeErr(w, errCode(err), err)
		return
	}
	writeJSON(w, http.StatusCreated, info)
}

func (h *handlers) listGateways(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, h.b.ListGateways())
}

func (h *handlers) getGateway(w http.ResponseWriter, r *http.Request, vlan int) {
	info, err := h.b.GetGateway(vlan)
	if err != nil {
		writeErr(w, errCode(err), err)
		return
	}
	writeJSON(w, http.StatusOK, info)
}

func (h *handlers) deleteGateway(w http.ResponseWriter, r *http.Request, vlan int) {
	if err := h.b.DeleteGateway(vlan); err != nil {
		writeErr(w, errCode(err), err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *handlers) addForward(w http.ResponseWriter, r *http.Request, vlan int) {
	var req ForwardRequest
	if !decodeBody(w, r, &req) {
		return
	}
	info, err := h.b.AddForward(vlan, req)
	if err != nil {
		writeErr(w, errCode(err), err)
		return
	}
	writeJSON(w, http.StatusCreated, info)
}

// replaceForwards is the declarative full-set update: PUT the desired list,
// the backend reconciles (keeps matching rules alive, removes extras, adds
// missing).
func (h *handlers) replaceForwards(w http.ResponseWriter, r *http.Request, vlan int) {
	var reqs []ForwardRequest
	if !decodeBody(w, r, &reqs) {
		return
	}
	infos, err := h.b.ReplaceForwards(vlan, reqs)
	if err != nil {
		writeErr(w, errCode(err), err)
		return
	}
	writeJSON(w, http.StatusOK, infos)
}

func (h *handlers) listForwards(w http.ResponseWriter, r *http.Request, vlan int) {
	infos, err := h.b.ListForwards(vlan)
	if err != nil {
		writeErr(w, errCode(err), err)
		return
	}
	writeJSON(w, http.StatusOK, infos)
}

func (h *handlers) deleteForward(w http.ResponseWriter, r *http.Request, vlan int) {
	if err := h.b.DeleteForward(vlan, r.PathValue("id")); err != nil {
		writeErr(w, errCode(err), err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *handlers) setDHCP(w http.ResponseWriter, r *http.Request, vlan, family int) {
	var err error
	if family == 4 {
		var cfg DHCP4Config
		if !decodeBody(w, r, &cfg) {
			return
		}
		err = h.b.SetDHCP4(vlan, cfg)
	} else {
		var cfg DHCP6Config
		if !decodeBody(w, r, &cfg) {
			return
		}
		err = h.b.SetDHCP6(vlan, cfg)
	}
	if err != nil {
		writeErr(w, errCode(err), err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *handlers) getDHCP(w http.ResponseWriter, r *http.Request, vlan, family int) {
	var (
		v   any
		err error
	)
	if family == 4 {
		v, err = h.b.GetDHCP4(vlan)
	} else {
		v, err = h.b.GetDHCP6(vlan)
	}
	if err != nil {
		writeErr(w, errCode(err), err)
		return
	}
	writeJSON(w, http.StatusOK, v)
}

func (h *handlers) putDHCPStatic(w http.ResponseWriter, r *http.Request, vlan, family int) {
	var b DHCPStaticBinding
	if !decodeBody(w, r, &b) {
		return
	}
	b.ID = r.PathValue("id")
	if err := h.b.PutDHCPStatic(vlan, family, b); err != nil {
		writeErr(w, errCode(err), err)
		return
	}
	writeJSON(w, http.StatusOK, b)
}

// replaceDHCPStatic atomically swaps the whole static-binding set (validated
// first; nothing changes on error).
func (h *handlers) replaceDHCPStatic(w http.ResponseWriter, r *http.Request, vlan, family int) {
	var bs []DHCPStaticBinding
	if !decodeBody(w, r, &bs) {
		return
	}
	if err := h.b.ReplaceDHCPStatic(vlan, family, bs); err != nil {
		writeErr(w, errCode(err), err)
		return
	}
	writeJSON(w, http.StatusOK, bs)
}

func (h *handlers) listDHCPStatic(w http.ResponseWriter, r *http.Request, vlan, family int) {
	bs, err := h.b.ListDHCPStatic(vlan, family)
	if err != nil {
		writeErr(w, errCode(err), err)
		return
	}
	writeJSON(w, http.StatusOK, bs)
}

func (h *handlers) deleteDHCPStatic(w http.ResponseWriter, r *http.Request, vlan, family int) {
	if err := h.b.DeleteDHCPStatic(vlan, family, r.PathValue("id")); err != nil {
		writeErr(w, errCode(err), err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *handlers) listDHCPLeases(w http.ResponseWriter, r *http.Request, vlan, family int) {
	ls, err := h.b.ListDHCPLeases(vlan, family)
	if err != nil {
		writeErr(w, errCode(err), err)
		return
	}
	writeJSON(w, http.StatusOK, ls)
}

func (h *handlers) deleteDHCPLease(w http.ResponseWriter, r *http.Request, vlan, family int) {
	if err := h.b.DeleteDHCPLease(vlan, family, r.PathValue("ip")); err != nil {
		writeErr(w, errCode(err), err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *handlers) setSLAAC(w http.ResponseWriter, r *http.Request, vlan int) {
	var cfg SLAACConfig
	if !decodeBody(w, r, &cfg) {
		return
	}
	if err := h.b.SetSLAAC(vlan, cfg); err != nil {
		writeErr(w, errCode(err), err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *handlers) getSLAAC(w http.ResponseWriter, r *http.Request, vlan int) {
	cfg, err := h.b.GetSLAAC(vlan)
	if err != nil {
		writeErr(w, errCode(err), err)
		return
	}
	writeJSON(w, http.StatusOK, cfg)
}
