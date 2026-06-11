package ports

import (
	"fmt"
	"os"
	"sync"

	"github.com/vishvananda/netlink"

	"github.com/HuJK/gvisor-vswitch/internal/switchcore"
)

// TapConfig describes a tap (or tap-on-linux-bridge) port. Requires
// CAP_NET_ADMIN.
type TapConfig struct {
	ID      string
	TapName string
	Bridge  string // tapbr: linux bridge to join
	AddToBr bool
}

// tapPort owns a kernel tap device; frames are pumped between the device fd
// and the switch.
type tapPort struct {
	id   string
	sw   *switchcore.Switch
	link netlink.Link

	mu   sync.Mutex
	pump *pump
}

// tapIO adapts the tap fd to frameIO: one read = one frame (IFF_NO_PI).
// Single-reader scratch buffer, frames copied out right-sized (see dgramIO).
type tapIO struct {
	f       *os.File
	scratch [maxFrameSize + 1]byte
}

func (t *tapIO) ReadFrame() ([]byte, error) {
	n, err := t.f.Read(t.scratch[:])
	if err != nil {
		return nil, err
	}
	frame := make([]byte, n)
	copy(frame, t.scratch[:n])
	return frame, nil
}

func (t *tapIO) WriteFrame(frame []byte) error {
	_, err := t.f.Write(frame)
	return err
}

func (t *tapIO) Close() error { return t.f.Close() }

// NewTap creates a tap device (and optionally joins it to a linux bridge)
// and attaches it as a switchport.
func NewTap(sw *switchcore.Switch, cfg TapConfig) (ManagedPort, error) {
	if cfg.TapName == "" {
		return nil, fmt.Errorf("tap transport requires tap_name")
	}
	if cfg.AddToBr && cfg.Bridge == "" {
		return nil, fmt.Errorf("tapbr transport requires bridge")
	}

	la := netlink.NewLinkAttrs()
	la.Name = cfg.TapName
	tap := &netlink.Tuntap{
		LinkAttrs: la,
		Mode:      netlink.TUNTAP_MODE_TAP,
		Flags:     netlink.TUNTAP_DEFAULTS | netlink.TUNTAP_NO_PI,
		Queues:    1,
	}
	if err := netlink.LinkAdd(tap); err != nil {
		return nil, fmt.Errorf("create tap %s: %w", cfg.TapName, err)
	}
	if len(tap.Fds) == 0 {
		netlink.LinkDel(tap)
		return nil, fmt.Errorf("create tap %s: no queue fd", cfg.TapName)
	}

	cleanup := func() {
		for _, f := range tap.Fds {
			f.Close()
		}
		netlink.LinkDel(tap)
	}

	if cfg.AddToBr {
		br, err := netlink.LinkByName(cfg.Bridge)
		if err != nil {
			cleanup()
			return nil, fmt.Errorf("bridge %s: %w", cfg.Bridge, err)
		}
		if _, ok := br.(*netlink.Bridge); !ok {
			cleanup()
			return nil, fmt.Errorf("%s is not a bridge", cfg.Bridge)
		}
		if err := netlink.LinkSetMaster(tap, br); err != nil {
			cleanup()
			return nil, fmt.Errorf("join %s to bridge %s: %w", cfg.TapName, cfg.Bridge, err)
		}
	}
	if err := netlink.LinkSetUp(tap); err != nil {
		cleanup()
		return nil, fmt.Errorf("set %s up: %w", cfg.TapName, err)
	}

	p := &tapPort{id: cfg.ID, sw: sw, link: tap}
	pmp := newPump(sw.Ref(cfg.ID), &tapIO{f: tap.Fds[0]}, func() {
		p.mu.Lock()
		p.pump = nil
		p.mu.Unlock()
		sw.NotifyDown(cfg.ID)
	})
	p.pump = pmp
	pmp.start()
	return p, nil
}

func (p *tapPort) ID() string { return p.id }

func (p *tapPort) Send(_ switchcore.Meta, frame []byte) bool {
	p.mu.Lock()
	pmp := p.pump
	p.mu.Unlock()
	if pmp == nil {
		return false
	}
	return pmp.send(frame)
}

func (p *tapPort) Close() error {
	p.mu.Lock()
	pmp := p.pump
	p.mu.Unlock()
	if pmp != nil {
		pmp.stop()
	}
	return netlink.LinkDel(p.link)
}

func (p *tapPort) Status() Status {
	p.mu.Lock()
	defer p.mu.Unlock()
	return Status{Online: p.pump != nil, Peer: p.link.Attrs().Name}
}
