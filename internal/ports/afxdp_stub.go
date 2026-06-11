//go:build !linux || (!amd64 && !arm64)

package ports

import (
	"fmt"

	"github.com/HuJK/gvisor-vswitch/internal/switchcore"
)

// AFXDPConfig describes an af_xdp port.
type AFXDPConfig struct {
	ID        string
	Interface string
	QueueID   int
}

// NewAFXDP is unsupported on this platform (AF_XDP needs linux amd64/arm64).
func NewAFXDP(sw *switchcore.Switch, cfg AFXDPConfig) (ManagedPort, error) {
	return nil, fmt.Errorf("af_xdp transport is not supported on this platform")
}
