// Package api exposes the REST control plane over a tcp or unix control
// socket.
package api

import (
	"encoding/json"
	"fmt"
	"net"
	"regexp"

	"github.com/HuJK/gvisor-vswitch/internal/switchcore"
)

// identifierRe restricts port identifiers so they are unambiguous in URL
// paths and in multiplex subport names (`<id>@<client>`).
var identifierRe = regexp.MustCompile(`^[A-Za-z0-9._-]+$`)

func ValidateIdentifier(id string) error {
	if !identifierRe.MatchString(id) {
		return fmt.Errorf("identifier must match %s", identifierRe)
	}
	return nil
}

// PortRequest creates a switchport.
type PortRequest struct {
	Identifier string `json:"identifier"`
	// VLAN: 0 = untagged-only, 1-4094 = access, 4095 = trunk.
	// Omitted = 4095 (trunk).
	VLAN     *int `json:"vlan,omitempty"`
	Isolated bool `json:"isolated,omitempty"`
	// PortSecurity: null = no source MAC check, otherwise the only
	// accepted source MAC.
	PortSecurity *string `json:"port_security,omitempty"`
	// Enabled: false administratively shuts the port (default true).
	Enabled *bool `json:"enabled,omitempty"`
	// AutoRemove (default true): when the port's transport becomes
	// unrecoverable — peer closed a stateful connection, tap device or
	// af_xdp interface deleted — the port is removed entirely, as if
	// DELETEd. Set false to keep it registered (e.g. a server port that
	// should keep listening for a reconnect). Datagram transports have no
	// disconnect signal, so this never triggers for them.
	AutoRemove *bool `json:"auto_remove,omitempty"`

	Mode      string `json:"mode"`      // client | server
	Transport string `json:"transport"` // tcp|udp|unix|unixgram|vsock|vsock-dgram|tap|tapbr
	// Local: client = optional bind address; server = listen address.
	Local string `json:"local,omitempty"`
	// Remote: client = dial target.
	Remote string `json:"remote,omitempty"`
	// ReplacingMode: server only; replace (default) | occupy | multiplex.
	ReplacingMode string `json:"replacing_mode,omitempty"`
	// TapName / Bridge: tap and tapbr transports.
	TapName string `json:"tap_name,omitempty"`
	Bridge  string `json:"bridge,omitempty"`
	// Interface / QueueID: af_xdp transport (take over a NIC; QueueID is
	// the RX queue to bind, default 0).
	Interface string `json:"interface,omitempty"`
	QueueID   int    `json:"queue_id,omitempty"`

	// Loop protection / spanning tree.
	BPDUGuard   bool   `json:"bpdu_guard,omitempty"`   // BPDU received -> port auto-disabled
	LoopDetect  bool   `json:"loop_detect,omitempty"`  // send loop probes out this port
	StormPPS    uint32 `json:"storm_pps,omitempty"`    // flooded-ingress rate limit (0 = off)
	STP         bool   `json:"stp,omitempty"`          // participate in spanning tree
	STPCost     uint32 `json:"stp_cost,omitempty"`     // path cost (default 100)
	STPPriority uint8  `json:"stp_priority,omitempty"` // port priority (default 128)
}

// Attrs converts the request's policy fields. An omitted vlan defaults to
// trunk (4095).
func (r *PortRequest) Attrs() (switchcore.PortAttrs, error) {
	attrs := switchcore.PortAttrs{
		Isolated: r.Isolated,
		VLAN:     switchcore.VLANTrunk,
	}
	if r.VLAN != nil {
		attrs.VLAN = *r.VLAN
	}
	if r.PortSecurity != nil {
		mac, err := net.ParseMAC(*r.PortSecurity)
		if err != nil {
			return attrs, fmt.Errorf("bad port_security MAC: %w", err)
		}
		attrs.SecurityMAC = mac
	}
	if r.Enabled != nil {
		attrs.Disabled = !*r.Enabled
	}
	attrs.BPDUGuard = r.BPDUGuard
	attrs.LoopDetect = r.LoopDetect
	attrs.StormPPS = r.StormPPS
	attrs.STP = r.STP
	attrs.STPCost = r.STPCost
	attrs.STPPriority = r.STPPriority
	return attrs, nil
}

// PortPatch updates policy attributes. Absent fields are unchanged; for
// port_security an explicit null is meaningful (security off), so it is a
// raw message.
type PortPatch struct {
	VLAN         *int            `json:"vlan,omitempty"` // 0 | 1-4094 | 4095
	Isolated     *bool           `json:"isolated,omitempty"`
	PortSecurity json.RawMessage `json:"port_security,omitempty"`
	Enabled      *bool           `json:"enabled,omitempty"`

	BPDUGuard   *bool   `json:"bpdu_guard,omitempty"`
	LoopDetect  *bool   `json:"loop_detect,omitempty"`
	StormPPS    *uint32 `json:"storm_pps,omitempty"`
	STP         *bool   `json:"stp,omitempty"`
	STPCost     *uint32 `json:"stp_cost,omitempty"`
	STPPriority *uint8  `json:"stp_priority,omitempty"`
}

// Apply merges the patch into attrs.
func (p *PortPatch) Apply(attrs switchcore.PortAttrs) (switchcore.PortAttrs, error) {
	if p.VLAN != nil {
		attrs.VLAN = *p.VLAN
	}
	if p.Isolated != nil {
		attrs.Isolated = *p.Isolated
	}
	if p.Enabled != nil {
		attrs.Disabled = !*p.Enabled
	}
	if p.BPDUGuard != nil {
		attrs.BPDUGuard = *p.BPDUGuard
	}
	if p.LoopDetect != nil {
		attrs.LoopDetect = *p.LoopDetect
	}
	if p.StormPPS != nil {
		attrs.StormPPS = *p.StormPPS
	}
	if p.STP != nil {
		attrs.STP = *p.STP
	}
	if p.STPCost != nil {
		attrs.STPCost = *p.STPCost
	}
	if p.STPPriority != nil {
		attrs.STPPriority = *p.STPPriority
	}
	if p.PortSecurity != nil {
		var s *string
		if err := json.Unmarshal(p.PortSecurity, &s); err != nil {
			return attrs, fmt.Errorf("bad port_security: %w", err)
		}
		if s == nil {
			attrs.SecurityMAC = nil
		} else {
			mac, err := net.ParseMAC(*s)
			if err != nil {
				return attrs, fmt.Errorf("bad port_security MAC: %w", err)
			}
			attrs.SecurityMAC = mac
		}
	}
	return attrs, nil
}

// PortInfo is the GET representation of a port.
type PortInfo struct {
	Identifier   string  `json:"identifier"`
	VLAN         int     `json:"vlan"` // 0 = untagged-only, 4095 = trunk
	Isolated     bool    `json:"isolated"`
	PortSecurity *string `json:"port_security"`
	Enabled      bool    `json:"enabled"`
	AutoRemove   bool    `json:"auto_remove"`

	Mode          string `json:"mode"`
	Transport     string `json:"transport"`
	Local         string `json:"local,omitempty"`
	Remote        string `json:"remote,omitempty"`
	ReplacingMode string `json:"replacing_mode,omitempty"`
	TapName       string `json:"tap_name,omitempty"`
	Bridge        string `json:"bridge,omitempty"`
	Interface     string `json:"interface,omitempty"`
	QueueID       int    `json:"queue_id,omitempty"`

	BPDUGuard   bool   `json:"bpdu_guard"`
	LoopDetect  bool   `json:"loop_detect"`
	StormPPS    uint32 `json:"storm_pps"`
	STP         bool   `json:"stp"`
	STPCost     uint32 `json:"stp_cost,omitempty"`
	STPPriority uint8  `json:"stp_priority,omitempty"`
	// STPState/STPRole reflect the spanning tree ("-" when not
	// participating); BlockedReason is set by bpdu_guard / loop detection.
	STPState      string `json:"stp_state,omitempty"`
	STPRole       string `json:"stp_role,omitempty"`
	BlockedReason string `json:"blocked_reason,omitempty"`

	Online      bool     `json:"online"`
	Peer        string   `json:"peer,omitempty"`
	Connections []string `json:"connections,omitempty"`

	Stats switchcore.PortStats `json:"stats"`
}

// FDBRow is one forwarding-database entry.
type FDBRow struct {
	VLAN       int    `json:"vlan"` // 0 = untagged domain
	MAC        string `json:"mac"`
	Port       string `json:"port"`
	AgeSeconds int    `json:"age_seconds"`
	Static     bool   `json:"static"`
}

// StaticFDBRequest installs an admin-managed forwarding entry.
type StaticFDBRequest struct {
	VLAN int    `json:"vlan"` // 0 = untagged domain, 1-4094 = that VLAN
	MAC  string `json:"mac"`
	Port string `json:"port"`
}

// FDBFlushRequest clears dynamic entries; empty filters match everything.
type FDBFlushRequest struct {
	Port string `json:"port,omitempty"`
	VLAN *int   `json:"vlan,omitempty"` // 0 = untagged domain
}

// FDBConfig is the forwarding-database tuning.
type FDBConfig struct {
	AgingSeconds int `json:"aging_seconds"`
}

// Error is the uniform error envelope.
type Error struct {
	Error string `json:"error"`
}
