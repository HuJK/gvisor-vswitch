package vhostuser

import (
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"sync"

	"golang.org/x/sys/unix"
)

const (
	rxQueue = 0 // device -> driver (receiveq)
	txQueue = 1 // driver -> device (transmitq)
	nQueues = 2

	maxFrameSize = 65535
)

// Handlers connect a NetDevice to its consumer (the switchport glue).
type Handlers struct {
	// Frame is called for every frame the guest transmits, outside of
	// device locks. The buffer is freshly allocated and owned by the
	// callee.
	Frame func([]byte)
	// State reports dataplane readiness changes (TX ring started, session
	// ended).
	State func(up bool)
}

// NetDevice is one vhost-user-net back-end session bound to one front-end
// connection (one VM).
//
// Locking: d.mu guards all ring/memory state. Guest memory is only touched
// with d.mu held and v.started true; teardown (which unmaps) flips started
// under the same lock, so the dataplane can never race an unmap. Frames are
// handed to Handlers.Frame outside the lock (a Deliver into the switch may
// fan out to another vhost port whose WriteFrame takes its own lock).
type NetDevice struct {
	conn     *net.UnixConn
	handlers Handlers

	mu            sync.Mutex
	features      uint64
	offered       uint64 // features we advertise (supportedFeatures [+ ACCESS_PLATFORM])
	protoFeatures uint64
	protoOn       bool // VHOST_USER_F_PROTOCOL_FEATURES negotiated
	mem           *memTable
	rings         [nQueues]*vring

	closed chan struct{}
	once   sync.Once
}

// NewNetDevice starts serving the vhost-user protocol on conn. The session
// runs until the connection drops or Close is called.
//
// accessPlatform advertises VIRTIO_F_ACCESS_PLATFORM. Enable it only for
// protected/pVM front-ends (e.g. crosvm on gunyah) where the guest must route
// virtio DMA through the platform DMA API so buffers land in the host-visible
// shared (swiotlb) region we can map. Leave it off for QEMU/normal front-ends:
// there ACCESS_PLATFORM means a vIOMMU and the front-end would demand the
// IOTLB/backend-req protocol we do not implement.
func NewNetDevice(conn *net.UnixConn, accessPlatform bool, h Handlers) *NetDevice {
	offered := uint64(supportedFeatures)
	if accessPlatform {
		offered |= featAccessPlatform
	}
	d := &NetDevice{
		conn:     conn,
		handlers: h,
		offered:  offered,
		closed:   make(chan struct{}),
	}
	for i := range d.rings {
		d.rings[i] = &vring{}
	}
	go d.serve()
	return d
}

// Close tears the session down.
func (d *NetDevice) Close() error {
	d.once.Do(func() {
		close(d.closed)
		d.conn.Close()
		d.mu.Lock()
		for _, v := range d.rings {
			d.stopRingLocked(v)
		}
		if d.mem != nil {
			d.mem.close()
			d.mem = nil
		}
		d.mu.Unlock()
	})
	return nil
}

func (d *NetDevice) serve() {
	defer func() {
		d.Close()
		if d.handlers.State != nil {
			d.handlers.State(false)
		}
	}()
	for {
		m, err := readMsg(d.conn)
		if err != nil {
			return
		}
		// handle owns m.fds and closes them exactly once.
		if err := d.handle(m); err != nil {
			return
		}
	}
}

// mrgRxbufLocked reports whether mergeable RX buffers were negotiated.
func (d *NetDevice) mrgRxbufLocked() bool {
	return d.features&featNetMrgRxbuf != 0
}

func (d *NetDevice) handle(m *message) error {
	// handle owns m.fds: paths that keep an fd take it out of m.fds, and
	// whatever remains (including stray fds on messages that should not
	// carry any) is closed exactly once here. Nothing else may close them;
	// a second close could hit an unrelated fd reusing the same number.
	defer func() {
		closeFds(m.fds)
		m.fds = nil
	}()

	d.mu.Lock()
	defer d.mu.Unlock()

	var (
		reply    []byte
		err      error
		hasReply bool
	)

	switch m.req {
	case reqGetFeatures:
		reply, hasReply = u64Payload(d.offered), true

	case reqSetFeatures:
		if len(m.payload) >= 8 {
			feats := binary.LittleEndian.Uint64(m.payload)
			// Reject any bit we did not offer (matches rust-vmm set_features).
			if feats&^d.offered != 0 {
				err = fmt.Errorf("set_features: unsupported bits %#x", feats&^d.offered)
			} else {
				d.features = feats
				d.protoOn = d.features&featProtocolFeatures != 0
			}
		}

	case reqGetProtocolFeatures:
		reply, hasReply = u64Payload(supportedProtocolFeatures), true

	case reqSetProtocolFeatures:
		if len(m.payload) >= 8 {
			d.protoFeatures = binary.LittleEndian.Uint64(m.payload)
		}

	case reqSetOwner, reqSetVringErr:
		// Accepted no-ops; any attached fds are closed by the deferred
		// cleanup. SET_LOG_BASE/SET_LOG_FD are *not* no-ops: LOG_SHMFD is
		// not offered, and SET_LOG_BASE expects a reply, so swallowing it
		// would hang the front-end. They fall through to the default.

	case reqResetOwner:
		for _, v := range d.rings {
			d.stopRingLocked(v)
		}

	case reqSetMemTable:
		err = d.setMemTableLocked(m)

	case reqSetVringNum:
		var idx, num uint32
		if idx, num, err = vringStatePayload(m.payload); err == nil {
			if v := d.ring(idx); v != nil && num > 0 && num <= 32768 && num&(num-1) == 0 {
				v.num = num
			} else {
				err = fmt.Errorf("bad vring num %d for ring %d", num, idx)
			}
		}

	case reqSetVringBase:
		var idx, base uint32
		if idx, base, err = vringStatePayload(m.payload); err == nil {
			if v := d.ring(idx); v != nil {
				v.lastAvail = uint16(base)
			}
		}

	case reqGetVringBase:
		var idx uint32
		if idx, _, err = vringStatePayload(m.payload); err == nil {
			if v := d.ring(idx); v != nil {
				d.stopRingLocked(v)
				out := make([]byte, 8)
				binary.LittleEndian.PutUint32(out[0:4], idx)
				binary.LittleEndian.PutUint32(out[4:8], uint32(v.lastAvail))
				reply, hasReply = out, true
			} else {
				// The front-end blocks on this reply; failing the session
				// (EOF) beats leaving it hung with no answer.
				err = fmt.Errorf("bad vring index %d", idx)
			}
		}

	case reqSetVringAddr:
		err = d.setVringAddrLocked(m.payload)

	case reqSetVringKick:
		err = d.setVringFDLocked(m, true)

	case reqSetVringCall:
		err = d.setVringFDLocked(m, false)

	case reqSetVringEnable:
		// QEMU's vhost-user-net disables rings (SET_VRING_ENABLE 0) during
		// its init phase, before SET_FEATURES is sent, so we must NOT gate
		// this on protocol-feature negotiation (rust-vmm's check_feature
		// gate rejects that legitimate early call). evalRingLocked already
		// honors v.enabled, so accepting it unconditionally is correct.
		var idx, on uint32
		if idx, on, err = vringStatePayload(m.payload); err == nil {
			if v := d.ring(idx); v != nil {
				v.enabled = on != 0
				if !v.enabled {
					v.started = false // pause; resumable
				} else {
					d.evalRingLocked(idx, v)
				}
			}
		}

	default:
		// Unknown or unsupported request. Some of these (the GET family)
		// expect a reply we cannot produce; erroring out closes the
		// session so the front-end sees EOF instead of hanging. This
		// matches rust-vmm, where unknown messages fail the connection.
		err = fmt.Errorf("unsupported request %d", m.req)
	}

	if hasReply {
		return writeReply(d.conn, m.req, reply)
	}
	// REPLY_ACK: requests carrying NEED_REPLY expect a u64 status. The
	// status reports the outcome; the error still propagates (failing the
	// session), matching the reference implementation.
	if m.flags&flagNeedReply != 0 && d.protoFeatures&protoFeatReplyAck != 0 {
		status := uint64(0)
		if err != nil {
			status = 1
		}
		if werr := writeReply(d.conn, m.req, u64Payload(status)); werr != nil {
			return werr
		}
	}
	return err
}

func (d *NetDevice) ring(idx uint32) *vring {
	if idx >= nQueues {
		return nil
	}
	return d.rings[idx]
}

func (d *NetDevice) setMemTableLocked(m *message) error {
	// The fds are only needed for the mmap calls; handle's deferred
	// cleanup closes them afterwards (the mappings stay valid).
	t, err := parseMemTable(m.payload, m.fds)
	if err != nil {
		return err
	}
	if d.mem != nil {
		// Stop rings before unmapping what they point into.
		for _, v := range d.rings {
			d.stopRingLocked(v)
		}
		d.mem.close()
	}
	d.mem = t
	for i, v := range d.rings {
		d.evalRingLocked(uint32(i), v)
	}
	return nil
}

func (d *NetDevice) setVringAddrLocked(payload []byte) error {
	a, err := parseVringAddr(payload)
	if err != nil {
		return err
	}
	v := d.ring(a.index)
	if v == nil {
		return fmt.Errorf("bad vring index %d", a.index)
	}
	if d.mem == nil || v.num == 0 {
		return fmt.Errorf("vring addr before mem table / num")
	}
	num := uint64(v.num)
	if v.desc, err = d.mem.uvaSlice(a.desc, num*descSize); err != nil {
		return fmt.Errorf("desc table: %w", err)
	}
	if v.avail, err = d.mem.uvaSlice(a.avail, 4+num*2+2); err != nil {
		return fmt.Errorf("avail ring: %w", err)
	}
	if v.used, err = d.mem.uvaSlice(a.used, 4+num*8+2); err != nil {
		return fmt.Errorf("used ring: %w", err)
	}
	// Resume from the driver-visible used index.
	v.usedIdx = uint16(atomicLoadU32(v.used) >> 16)
	d.evalRingLocked(a.index, v)
	return nil
}

func (d *NetDevice) setVringFDLocked(m *message, isKick bool) error {
	if len(m.payload) < 8 {
		return fmt.Errorf("short vring fd payload")
	}
	val := binary.LittleEndian.Uint64(m.payload)
	idx := uint32(val & vringIdxMask)
	v := d.ring(idx)
	if v == nil {
		return fmt.Errorf("bad vring index %d", idx)
	}

	var f *os.File
	if val&invalidFDFlag == 0 {
		if len(m.fds) < 1 {
			return fmt.Errorf("vring fd message without fd")
		}
		unix.SetNonblock(m.fds[0], true)
		name := "vhost-call"
		if isKick {
			name = "vhost-kick"
		}
		// Take ownership of fds[0]; the rest stay on m.fds for the
		// deferred cleanup.
		f = os.NewFile(uintptr(m.fds[0]), name)
		m.fds = m.fds[1:]
	}

	if isKick {
		if v.kick != nil {
			// Replacing the kick fd: closing the old one makes any
			// pump reading it exit; a new pump starts below.
			v.started = false
			v.kick.Close()
		}
		v.kick = f
	} else {
		if v.call != nil {
			v.call.Close()
		}
		v.call = f
	}
	d.evalRingLocked(idx, v)
	return nil
}

// evalRingLocked starts a ring once everything it needs is in place. With
// protocol features negotiated, rings start disabled until
// SET_VRING_ENABLE; without, setting the kick fd implies enabled.
func (d *NetDevice) evalRingLocked(idx uint32, v *vring) {
	if v.started {
		return
	}
	if d.mem == nil || v.num == 0 || v.desc == nil || v.kick == nil {
		return
	}
	if d.protoOn && !v.enabled {
		return
	}
	v.started = true
	if idx == txQueue {
		if !v.pumpRunning {
			v.pumpRunning = true
			go d.txPump(v, v.kick)
		} else {
			// The pump keeps reading the kick eventfd while the ring is
			// paused (SET_VRING_ENABLE(0)), so guest kicks from that
			// window were consumed without draining. Poke the eventfd so
			// chains queued during the pause are processed now.
			var one [8]byte
			one[0] = 1
			v.kick.Write(one[:])
		}
		if d.handlers.State != nil {
			go d.handlers.State(true)
		}
	}
}

func (d *NetDevice) stopRingLocked(v *vring) {
	v.started = false
	if v.kick != nil {
		v.kick.Close() // unblocks the pump's eventfd read -> pump exits
		v.kick = nil
	}
	if v.call != nil {
		v.call.Close()
		v.call = nil
	}
	v.desc, v.avail, v.used = nil, nil, nil
	v.enabled = false
}

// txPump consumes guest-transmitted frames: drain everything available,
// deliver outside the lock, then block on the kick eventfd. It exits when
// its kick fd is closed (ring stop, fd replacement or session end).
func (d *NetDevice) txPump(v *vring, kick *os.File) {
	defer func() {
		d.mu.Lock()
		v.pumpRunning = false
		// Kick fd was replaced while the ring stayed live: hand over to
		// a fresh pump on the new fd.
		if v.started && v.kick != nil {
			v.pumpRunning = true
			go d.txPump(v, v.kick)
		}
		d.mu.Unlock()
	}()
	var eventBuf [8]byte
	for {
		d.mu.Lock()
		var frames [][]byte
		if v.started && d.mem != nil {
			frames = d.drainTXLocked(v)
		}
		d.mu.Unlock()

		for _, f := range frames {
			if d.handlers.Frame != nil {
				d.handlers.Frame(f)
			}
		}

		if _, err := kick.Read(eventBuf[:]); err != nil {
			return // kick fd closed
		}
	}
}

// drainTXLocked consumes all available TX chains, returning copied frames.
func (d *NetDevice) drainTXLocked(v *vring) [][]byte {
	var frames [][]byte
	count := 0
	for {
		head, ok := v.popAvail()
		if !ok {
			break
		}
		if c, err := v.resolveChain(d.mem, head); err == nil {
			if frame := gatherTX(c); frame != nil {
				frames = append(frames, frame)
			}
		}
		v.setUsedElem(0, head, 0)
		v.publishUsed(1)
		count++
	}
	if count > 0 {
		v.notify()
	}
	return frames
}

// gatherTX copies a transmitted frame out of the chain's readable
// segments, skipping the leading virtio-net header.
func gatherTX(c chain) []byte {
	total := 0
	for _, s := range c.readable {
		total += len(s)
	}
	if total <= virtioNetHdrSize || total-virtioNetHdrSize > maxFrameSize {
		return nil
	}
	frame := make([]byte, 0, total-virtioNetHdrSize)
	skip := virtioNetHdrSize
	for _, s := range c.readable {
		if skip >= len(s) {
			skip -= len(s)
			continue
		}
		frame = append(frame, s[skip:]...)
		skip = 0
	}
	return frame
}

// WriteFrame delivers a frame into the guest's receive queue, spreading it
// over as many buffers as needed (VIRTIO_NET_F_MRG_RXBUF). It reports
// false when the dataplane is down or out of buffers (frame dropped).
func (d *NetDevice) WriteFrame(frame []byte) bool {
	if len(frame) > maxFrameSize {
		return false
	}
	d.mu.Lock()
	defer d.mu.Unlock()

	v := d.rings[rxQueue]
	if !v.started || d.mem == nil {
		return false
	}

	var hdr [virtioNetHdrSize]byte
	type usedChain struct {
		head    uint16
		written uint32
	}
	var (
		used      []usedChain
		hdrSeg    []byte // first segment, for the num_buffers patch
		remaining = virtioNetHdrSize + len(frame)
		src       = frame
		hdrLeft   = virtioNetHdrSize
	)

	startAvail := v.lastAvail
	for remaining > 0 {
		if !d.mrgRxbufLocked() && len(used) == 1 {
			break // single-buffer mode and the frame didn't fit
		}
		head, ok := v.popAvail()
		if !ok {
			break
		}
		c, err := v.resolveChain(d.mem, head)
		if err != nil {
			// Malformed chain: return every chain consumed so far
			// (zero-length) so the driver gets its buffers back, and
			// drop the frame.
			used = append(used, usedChain{head: head})
			for i, u := range used {
				v.setUsedElem(uint16(i), u.head, 0)
			}
			v.publishUsed(uint16(len(used)))
			v.notify()
			return false
		}
		written := uint32(0)
		for _, seg := range c.writable {
			for len(seg) > 0 && remaining > 0 {
				var n int
				if hdrLeft > 0 {
					n = copy(seg, hdr[virtioNetHdrSize-hdrLeft:])
					if hdrSeg == nil {
						hdrSeg = seg
					}
					hdrLeft -= n
				} else {
					n = copy(seg, src)
					src = src[n:]
				}
				seg = seg[n:]
				remaining -= n
				written += uint32(n)
			}
			if remaining == 0 {
				break
			}
		}
		used = append(used, usedChain{head: head, written: written})
	}

	if remaining > 0 {
		// Out of buffers: leave the chains in the avail ring for the
		// next frame, drop this one.
		v.lastAvail = startAvail
		return false
	}

	// num_buffers lives in the header already placed in guest memory.
	if len(hdrSeg) >= virtioNetHdrSize {
		binary.LittleEndian.PutUint16(hdrSeg[10:12], uint16(len(used)))
	}

	for i, u := range used {
		v.setUsedElem(uint16(i), u.head, u.written)
	}
	v.publishUsed(uint16(len(used)))
	v.notify()
	return true
}
