// Package ports implements the transport side of switchports: stream and
// datagram sockets (tcp/udp/unix/unixgram, later vsock and tap) in client
// (dial) and server (listen) mode. Stream transports carry ethernet frames
// with a QEMU-compatible 4-byte big-endian length prefix; datagram
// transports carry one frame per datagram.
package ports

import (
	"fmt"

	"github.com/HuJK/gvisor-vswitch/internal/switchcore"
)

// ReplacingMode controls how a server port treats additional clients.
type ReplacingMode string

const (
	// ModeReplace kicks the existing client when a new one arrives.
	ModeReplace ReplacingMode = "replace"
	// ModeOccupy rejects new clients while one is connected.
	ModeOccupy ReplacingMode = "occupy"
	// ModeMultiplex accepts many clients, each becoming its own switchport
	// named `<id>@<client>` (stream transports only).
	ModeMultiplex ReplacingMode = "multiplex"
)

// Status is a snapshot of a port's transport state.
type Status struct {
	Online bool `json:"online"`
	// Peer describes the connected remote, when known.
	Peer string `json:"peer,omitempty"`
	// Connections lists multiplex subport IDs.
	Connections []string `json:"connections,omitempty"`
}

// ManagedPort is a switchcore.Port with transport status, tracked by the
// manager.
type ManagedPort interface {
	switchcore.Port
	Status() Status
}

// SubAttrsUpdater is implemented by server ports that register multiplex
// subports: when the parent port's attributes change, subports follow.
type SubAttrsUpdater interface {
	UpdateSubAttrs(attrs switchcore.PortAttrs)
}

func isStreamTransport(t string) bool {
	switch t {
	case "tcp", "unix", "vsock":
		return true
	}
	return false
}

func isDgramTransport(t string) bool {
	switch t {
	case "udp", "unixgram", "vsock-dgram":
		return true
	}
	return false
}

func validateTransport(t string) error {
	if !isStreamTransport(t) && !isDgramTransport(t) {
		return fmt.Errorf("unknown transport %q", t)
	}
	return nil
}
