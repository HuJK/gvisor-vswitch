package ports

import (
	"fmt"
	"net"
	"sync"

	"github.com/HuJK/gvisor-vswitch/internal/switchcore"
)

// ClientConfig describes a client-mode (dialing) port.
type ClientConfig struct {
	ID        string
	Transport string // tcp | udp | unix | unixgram | vsock | vsock-dgram
	Local     string // optional bind (required for unixgram)
	Remote    string // dial target
}

// clientPort is a port backed by a single dialed connection. When the
// connection dies the port stays registered but goes offline.
type clientPort struct {
	id string
	sw *switchcore.Switch

	mu   sync.Mutex
	pump *pump
	peer string
}

// NewClient dials cfg.Remote and returns the port. The connection attempt
// is synchronous so the API can report success or failure directly.
func NewClient(sw *switchcore.Switch, cfg ClientConfig) (ManagedPort, error) {
	if err := validateTransport(cfg.Transport); err != nil {
		return nil, err
	}

	var (
		conn net.Conn
		err  error
	)
	if isStreamTransport(cfg.Transport) {
		conn, err = dialStream(cfg.Transport, cfg.Local, cfg.Remote)
	} else {
		conn, err = dialDgram(cfg.Transport, cfg.Local, cfg.Remote)
	}
	if err != nil {
		return nil, fmt.Errorf("dial %s %s: %w", cfg.Transport, cfg.Remote, err)
	}

	p := &clientPort{id: cfg.ID, sw: sw}

	var fio frameIO
	if isStreamTransport(cfg.Transport) {
		fio = newStreamIO(conn)
	} else {
		fio = &dgramIO{conn: conn}
	}
	pmp := newPump(sw.Ref(cfg.ID), fio, func() {
		p.mu.Lock()
		p.pump = nil
		p.mu.Unlock()
		sw.NotifyDown(cfg.ID)
	})
	p.pump = pmp
	p.peer = conn.RemoteAddr().String()
	pmp.start()
	return p, nil
}

func (p *clientPort) ID() string { return p.id }

func (p *clientPort) Send(_ switchcore.Meta, frame []byte) bool {
	p.mu.Lock()
	pmp := p.pump
	p.mu.Unlock()
	if pmp == nil {
		return false
	}
	return pmp.send(frame)
}

func (p *clientPort) Close() error {
	p.mu.Lock()
	pmp := p.pump
	p.mu.Unlock()
	if pmp != nil {
		pmp.stop()
	}
	return nil
}

func (p *clientPort) Status() Status {
	p.mu.Lock()
	defer p.mu.Unlock()
	return Status{Online: p.pump != nil, Peer: p.peer}
}
