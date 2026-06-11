// Package switchcore implements a VLAN-aware learning L2 switch. Ports feed
// received frames into Switch.Deliver and get frames to transmit through
// their Send method. The switch owns all forwarding policy: VLAN
// classification and rewriting, port security, isolation, and the FDB.
package switchcore

import (
	"fmt"
	"net"
)

// Meta accompanies every frame handed to a port. SrcPortID lets the gateway's
// DHCP server tie leases to the switchport a request came in on.
type Meta struct {
	SrcPortID string
}

// Port is the transport side of a switchport. Implementations move frames;
// all switching policy lives in the Switch. A frame passed to Send is owned
// by the switch and must not be modified; a frame passed to Deliver is owned
// by the switch afterwards and must not be reused by the caller.
type Port interface {
	ID() string
	// Send enqueues a frame for transmission. It must not block; it
	// reports false if the frame was dropped (e.g. queue full, offline).
	Send(meta Meta, frame []byte) bool
	Close() error
}

const (
	// VLANUntaggedOnly (0) accepts and emits only untagged frames (the
	// untagged domain).
	VLANUntaggedOnly = 0
	// VLANTrunk (4095) passes tagged frames as-is and groups untagged
	// frames into the untagged domain.
	VLANTrunk = 4095
)

// PortAttrs are the policy attributes of a switchport.
type PortAttrs struct {
	// SecurityMAC, when non-nil, drops ingress frames whose source MAC
	// differs.
	SecurityMAC net.HardwareAddr
	// Isolated ports can only exchange frames with non-isolated ports.
	Isolated bool
	// VLAN is VLANUntaggedOnly (0), an access VLAN 1-4094, or
	// VLANTrunk (4095).
	VLAN int
	// Disabled administratively shuts the port: no frames in or out.
	Disabled bool
}

// PortStats are per-port traffic counters (frames the switch saw from and
// sent to the port's transport).
type PortStats struct {
	RxFrames  uint64 `json:"rx_frames"`
	RxBytes   uint64 `json:"rx_bytes"`
	RxDropped uint64 `json:"rx_dropped"`
	TxFrames  uint64 `json:"tx_frames"`
	TxBytes   uint64 `json:"tx_bytes"`
	TxDropped uint64 `json:"tx_dropped"`
}

func (a PortAttrs) validate() error {
	if a.SecurityMAC != nil && len(a.SecurityMAC) != 6 {
		return fmt.Errorf("port-security MAC must be 6 bytes, got %d", len(a.SecurityMAC))
	}
	if a.VLAN < 0 || a.VLAN > VLANTrunk {
		return fmt.Errorf("vlan must be 0 (untagged-only), 1-4094 (access) or 4095 (trunk), got %d", a.VLAN)
	}
	return nil
}
