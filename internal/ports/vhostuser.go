package ports

import (
	"fmt"
	"net"
	"sync"

	"github.com/HuJK/gvisor-vswitch/internal/switchcore"
	"github.com/HuJK/gvisor-vswitch/internal/vhostuser"
)

// vhost-user transport: gvswitch is the virtio-net device back-end, the
// VMM (QEMU/crosvm) is the front-end. Server mode listens for the VMM;
// client mode dials a VMM started with server=on. Frames move through
// shared guest memory: no per-frame syscalls (eventfd kicks only).

// VhostUserConfig describes a vhost-user port.
type VhostUserConfig struct {
	ID   string
	Mode string // client | server
	// Path is the unix socket: listen path (server) or dial target
	// (client).
	Path          string
	ReplacingMode ReplacingMode // server only: replace | occupy
	// AccessPlatform advertises VIRTIO_F_ACCESS_PLATFORM to the front-end.
	// Required for protected/pVM front-ends (crosvm on gunyah) so the guest
	// routes virtio DMA through the platform DMA API into the host-visible
	// shared (swiotlb) region. Leave false for QEMU/normal front-ends.
	AccessPlatform bool
}

type vhostUserPort struct {
	id             string
	sw             *switchcore.Switch
	ref            *switchcore.PortRef
	mode           ReplacingMode
	accessPlatform bool

	ln net.Listener // server mode

	mu     sync.Mutex
	dev    *vhostuser.NetDevice
	up     bool // dataplane (TX ring) running
	peer   string
	closed bool
}

// NewVhostUser creates a vhost-user backend port.
func NewVhostUser(sw *switchcore.Switch, cfg VhostUserConfig) (ManagedPort, error) {
	p := &vhostUserPort{id: cfg.ID, sw: sw, ref: sw.Ref(cfg.ID), mode: cfg.ReplacingMode, accessPlatform: cfg.AccessPlatform}

	switch cfg.Mode {
	case "client":
		raddr := &net.UnixAddr{Name: cfg.Path, Net: "unix"}
		conn, err := net.DialUnix("unix", nil, raddr)
		if err != nil {
			return nil, fmt.Errorf("vhost-user dial %s: %w", cfg.Path, err)
		}
		p.adopt(conn)
		return p, nil

	case "server":
		switch cfg.ReplacingMode {
		case "", ModeReplace, ModeOccupy:
		default:
			return nil, fmt.Errorf("vhost-user supports replace/occupy only (one VM session per port)")
		}
		removeStaleSocket(cfg.Path)
		ln, err := net.Listen("unix", cfg.Path)
		if err != nil {
			return nil, fmt.Errorf("vhost-user listen %s: %w", cfg.Path, err)
		}
		p.ln = ln
		go p.acceptLoop()
		return p, nil
	}
	return nil, fmt.Errorf("mode must be \"client\" or \"server\", got %q", cfg.Mode)
}

func (p *vhostUserPort) acceptLoop() {
	for {
		conn, err := p.ln.Accept()
		if err != nil {
			return // listener closed
		}
		uconn := conn.(*net.UnixConn)

		p.mu.Lock()
		if p.closed {
			p.mu.Unlock()
			uconn.Close()
			return
		}
		if p.dev != nil {
			if p.mode == ModeOccupy {
				p.mu.Unlock()
				uconn.Close()
				continue
			}
			old := p.dev
			p.dev = nil
			p.mu.Unlock()
			old.Close()
			p.mu.Lock()
			if p.closed || p.dev != nil {
				p.mu.Unlock()
				uconn.Close()
				continue
			}
		}
		p.mu.Unlock()
		p.adopt(uconn)
	}
}

// adopt installs conn as the active vhost-user session.
func (p *vhostUserPort) adopt(conn *net.UnixConn) {
	p.mu.Lock()
	defer p.mu.Unlock()

	var dev *vhostuser.NetDevice
	dev = vhostuser.NewNetDevice(conn, p.accessPlatform, vhostuser.Handlers{
		Frame: func(frame []byte) {
			p.ref.Deliver(frame)
		},
		State: func(up bool) {
			p.mu.Lock()
			if p.dev != dev {
				p.mu.Unlock()
				return // stale session
			}
			wasUp := p.up
			p.up = up
			if !up {
				p.dev = nil
			}
			p.mu.Unlock()
			if wasUp && !up {
				p.sw.NotifyDown(p.id)
			}
		},
	})
	p.dev = dev
	p.peer = "vhost-user"
}

func (p *vhostUserPort) ID() string { return p.id }

func (p *vhostUserPort) Send(_ switchcore.Meta, frame []byte) bool {
	p.mu.Lock()
	dev := p.dev
	p.mu.Unlock()
	if dev == nil {
		return false
	}
	return dev.WriteFrame(frame)
}

func (p *vhostUserPort) Close() error {
	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		return nil
	}
	p.closed = true
	dev := p.dev
	p.dev = nil
	p.mu.Unlock()

	if p.ln != nil {
		p.ln.Close()
	}
	if dev != nil {
		dev.Close()
	}
	return nil
}

func (p *vhostUserPort) Status() Status {
	p.mu.Lock()
	defer p.mu.Unlock()
	st := Status{Online: p.dev != nil && p.up}
	if p.dev != nil {
		st.Peer = p.peer
	}
	return st
}
