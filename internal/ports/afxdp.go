//go:build linux && (amd64 || arm64)

package ports

import (
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/link"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/xdp"

	"github.com/HuJK/gvisor-vswitch/internal/switchcore"
)

// AF_XDP port: takes over a NIC by attaching an XDP program that redirects
// every ingress frame on the bound queue to an AF_XDP socket; egress frames
// are written to the socket's TX ring. The NIC is put into promiscuous mode
// so frames for any MAC reach the switch. Requires root (CAP_NET_ADMIN +
// CAP_BPF) and a kernel with AF_XDP (generic/copy mode works on any driver,
// including veth).

const (
	xdpActionPass = 2 // XDP_PASS: fallback for queues without a socket
	// rxQueueIndexOffset is offsetof(struct xdp_md, rx_queue_index).
	rxQueueIndexOffset = 16
	afxdpMaxQueues     = 64
	afxdpPollTimeout   = 500 // ms; bounds shutdown latency of the RX loop
)

// AFXDPConfig describes an af_xdp port.
type AFXDPConfig struct {
	ID        string
	Interface string
	QueueID   int
}

type afxdpPort struct {
	id      string
	sw      *switchcore.Switch
	ref     *switchcore.PortRef
	iface   string
	ifindex int

	cb      *xdp.ControlBlock
	sockFD  int
	prog    *ebpf.Program
	xskMap  *ebpf.Map
	xdpLink link.Link

	nlLink     netlink.Link
	setPromisc bool // whether we enabled promisc (to restore on close)

	closed chan struct{}
	once   sync.Once
}

// buildRedirectObjects creates the XSK map and a minimal XDP program:
//
//	return bpf_redirect_map(&xsks_map, ctx->rx_queue_index, XDP_PASS);
func buildRedirectObjects() (*ebpf.Map, *ebpf.Program, error) {
	xskMap, err := ebpf.NewMap(&ebpf.MapSpec{
		Name:       "gvsw_xsks",
		Type:       ebpf.XSKMap,
		KeySize:    4,
		ValueSize:  4,
		MaxEntries: afxdpMaxQueues,
	})
	if err != nil {
		return nil, nil, fmt.Errorf("create XSK map: %w", err)
	}
	prog, err := ebpf.NewProgram(&ebpf.ProgramSpec{
		Name: "gvsw_redirect",
		Type: ebpf.XDP,
		Instructions: asm.Instructions{
			asm.LoadMem(asm.R2, asm.R1, rxQueueIndexOffset, asm.Word),
			asm.LoadMapPtr(asm.R1, xskMap.FD()),
			asm.Mov.Imm(asm.R3, xdpActionPass),
			asm.FnRedirectMap.Call(),
			asm.Return(),
		},
		License: "Apache-2.0",
	})
	if err != nil {
		xskMap.Close()
		return nil, nil, fmt.Errorf("load XDP program: %w", err)
	}
	return xskMap, prog, nil
}

// NewAFXDP attaches to cfg.Interface and returns the port.
func NewAFXDP(sw *switchcore.Switch, cfg AFXDPConfig) (ManagedPort, error) {
	if cfg.Interface == "" {
		return nil, fmt.Errorf("af_xdp transport requires interface")
	}
	if cfg.QueueID < 0 || cfg.QueueID >= afxdpMaxQueues {
		return nil, fmt.Errorf("af_xdp queue_id must be 0-%d", afxdpMaxQueues-1)
	}

	nlLink, err := netlink.LinkByName(cfg.Interface)
	if err != nil {
		return nil, fmt.Errorf("interface %s: %w", cfg.Interface, err)
	}
	if err := netlink.LinkSetUp(nlLink); err != nil {
		return nil, fmt.Errorf("set %s up: %w", cfg.Interface, err)
	}

	p := &afxdpPort{
		id:      cfg.ID,
		sw:      sw,
		ref:     sw.Ref(cfg.ID),
		iface:   cfg.Interface,
		ifindex: nlLink.Attrs().Index,
		nlLink:  nlLink,
		closed:  make(chan struct{}),
	}
	fail := func(err error) (ManagedPort, error) {
		p.teardown()
		return nil, err
	}

	// The switch forwards frames for arbitrary MACs through this port.
	if nlLink.Attrs().Promisc == 0 {
		if err := netlink.SetPromiscOn(nlLink); err != nil {
			return fail(fmt.Errorf("set %s promisc: %w", cfg.Interface, err))
		}
		p.setPromisc = true
	}

	if p.xskMap, p.prog, err = buildRedirectObjects(); err != nil {
		return fail(err)
	}

	ifindex := nlLink.Attrs().Index
	p.xdpLink, err = link.AttachXDP(link.XDPOptions{Program: p.prog, Interface: ifindex})
	if err != nil {
		// Driver-native mode unsupported: fall back to generic (skb).
		p.xdpLink, err = link.AttachXDP(link.XDPOptions{
			Program:   p.prog,
			Interface: ifindex,
			Flags:     link.XDPGenericMode,
		})
		if err != nil {
			return fail(fmt.Errorf("attach XDP to %s: %w", cfg.Interface, err))
		}
	}

	opts := xdp.DefaultOpts()
	opts.Bind = true
	opts.UseNeedWakeup = true
	p.cb, err = xdp.New(uint32(ifindex), uint32(cfg.QueueID), opts)
	if err != nil {
		return fail(fmt.Errorf("AF_XDP socket on %s queue %d: %w", cfg.Interface, cfg.QueueID, err))
	}
	p.sockFD = int(p.cb.UMEM.SockFD())

	key := uint32(cfg.QueueID)
	val := p.cb.UMEM.SockFD()
	if err := p.xskMap.Update(&key, &val, 0); err != nil {
		return fail(fmt.Errorf("register socket in XSK map: %w", err))
	}

	p.cb.UMEM.Lock()
	p.cb.Fill.FillAll(&p.cb.UMEM)
	p.cb.UMEM.Unlock()

	// Prefer event-driven link-removal detection (netlink RTM_DELLINK);
	// fall back to periodic existence checks in the RX loop only when the
	// subscription cannot be established.
	pollFallback := !p.watchLink()

	go p.rxLoop(p.sockFD, pollFallback)
	return p, nil
}

// watchLink subscribes to netlink link updates and takes the port offline
// the moment the interface is deleted (hotplug removal, qemu shutdown).
// Returns false if the subscription could not be set up.
func (p *afxdpPort) watchLink() bool {
	ch := make(chan netlink.LinkUpdate, 16)
	if err := netlink.LinkSubscribe(ch, p.closed); err != nil {
		return false
	}
	go func() {
		for {
			select {
			case <-p.closed:
				return
			case u, ok := <-ch:
				if !ok {
					return
				}
				if u.Header.Type == unix.RTM_DELLINK && u.Link.Attrs().Index == p.ifindex {
					p.linkGone()
					return
				}
			}
		}
	}()
	return true
}

// linkGone takes the port offline after its interface vanished.
func (p *afxdpPort) linkGone() {
	select {
	case <-p.closed:
		return
	default:
	}
	p.Close()
	p.sw.NotifyDown(p.id)
}

func (p *afxdpPort) rxLoop(sockFD int, pollFallback bool) {
	// With pollFallback the interface-existence check runs roughly every
	// 2 seconds (no netlink subscription); otherwise the netlink watcher
	// handles removal and only POLLERR triggers a verification here.
	idleTicks := 0
	for {
		pfds := []unix.PollFd{{Fd: int32(sockFD), Events: unix.POLLIN}}
		n, err := unix.Poll(pfds, afxdpPollTimeout)
		if err != nil && !errors.Is(err, unix.EINTR) {
			return // socket closed
		}
		select {
		case <-p.closed:
			return
		default:
		}

		if n > 0 && pfds[0].Revents&(unix.POLLERR|unix.POLLHUP) != 0 {
			if !p.linkExists() {
				p.linkGone()
				return
			}
			// Persistent POLLERR with a live link: back off instead
			// of spinning.
			time.Sleep(100 * time.Millisecond)
		} else if pollFallback && n == 0 {
			if idleTicks++; idleTicks >= 4 {
				idleTicks = 0
				if !p.linkExists() {
					p.linkGone()
					return
				}
			}
		}
		if n == 0 {
			continue
		}

		nReceived, rxIndex := p.cb.RX.Peek()
		if nReceived == 0 {
			continue
		}
		frames := make([][]byte, 0, nReceived)
		p.cb.UMEM.Lock()
		for i := uint32(0); i < nReceived; i++ {
			desc := p.cb.RX.Get(rxIndex + i)
			data := p.cb.UMEM.Get(desc)
			frames = append(frames, append([]byte(nil), data...))
			p.cb.UMEM.FreeFrame(desc.Addr)
		}
		p.cb.Fill.FillAll(&p.cb.UMEM)
		p.cb.UMEM.Unlock()
		p.cb.RX.Release(nReceived)

		for _, f := range frames {
			p.ref.Deliver(f)
		}
	}
}

func (p *afxdpPort) linkExists() bool {
	_, err := netlink.LinkByIndex(p.ifindex)
	return err == nil
}

func (p *afxdpPort) ID() string { return p.id }

func (p *afxdpPort) Send(_ switchcore.Meta, frame []byte) bool {
	select {
	case <-p.closed:
		return false
	default:
	}
	// Frames must fit a UMEM frame (4096) minus the kernel's headroom.
	if len(frame) > 3584 {
		return false
	}
	p.cb.UMEM.Lock()
	p.cb.Completion.FreeAll(&p.cb.UMEM)
	nReserved, index := p.cb.TX.Reserve(&p.cb.UMEM, 1)
	if nReserved == 0 {
		p.cb.UMEM.Unlock()
		return false
	}
	desc := unix.XDPDesc{
		Addr: p.cb.UMEM.AllocFrame(),
		Len:  uint32(len(frame)),
	}
	copy(p.cb.UMEM.Get(desc), frame)
	p.cb.TX.Set(index, desc)
	p.cb.UMEM.Unlock()
	p.cb.TX.Notify()
	return true
}

func (p *afxdpPort) Close() error {
	p.once.Do(func() {
		close(p.closed)
		p.teardown()
	})
	return nil
}

// teardown releases kernel resources. It runs at most once: either from the
// constructor's failure path (before the RX goroutine exists) or from Close.
func (p *afxdpPort) teardown() {
	if p.sockFD > 0 {
		unix.Close(p.sockFD)
	}
	if p.xdpLink != nil {
		p.xdpLink.Close()
	}
	if p.prog != nil {
		p.prog.Close()
	}
	if p.xskMap != nil {
		p.xskMap.Close()
	}
	if p.setPromisc {
		netlink.SetPromiscOff(p.nlLink)
	}
}

func (p *afxdpPort) Status() Status {
	select {
	case <-p.closed:
		return Status{Online: false, Peer: p.iface}
	default:
		return Status{Online: true, Peer: p.iface}
	}
}
