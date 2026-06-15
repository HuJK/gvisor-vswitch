package vhostuser

import (
	"bytes"
	"encoding/binary"
	"net"
	"os"
	"testing"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
)

// fakeFrontEnd plays QEMU's role: it owns "guest memory" (a memfd mapped
// into the test process), drives the control protocol, and acts as the
// guest driver on the rings.
type fakeFrontEnd struct {
	t    *testing.T
	conn *net.UnixConn

	memfd int
	mem   []byte

	kick [nQueues]*os.File
	call [nQueues]*os.File
}

const (
	feMemSize = 4 << 20
	feRingNum = 8
	feQ0Desc  = 0x0000
	feQ0Avail = 0x1000
	feQ0Used  = 0x2000
	feQ1Desc  = 0x3000
	feQ1Avail = 0x4000
	feQ1Used  = 0x5000
	feBufBase = 0x10000
	feGPABase = 0 // guest physical addresses == offsets in mem
)

func ringOffsets(q int) (desc, avail, used uint64) {
	if q == 0 {
		return feQ0Desc, feQ0Avail, feQ0Used
	}
	return feQ1Desc, feQ1Avail, feQ1Used
}

func newFakeFrontEnd(t *testing.T) (*fakeFrontEnd, *net.UnixConn) {
	t.Helper()
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	mkConn := func(fd int, name string) *net.UnixConn {
		f := os.NewFile(uintptr(fd), name)
		defer f.Close()
		c, err := net.FileConn(f)
		if err != nil {
			t.Fatal(err)
		}
		return c.(*net.UnixConn)
	}
	feConn := mkConn(fds[0], "front-end")
	devConn := mkConn(fds[1], "back-end")

	memfd, err := unix.MemfdCreate("guest-ram", unix.MFD_CLOEXEC)
	if err != nil {
		t.Fatal(err)
	}
	if err := unix.Ftruncate(memfd, feMemSize); err != nil {
		t.Fatal(err)
	}
	mem, err := unix.Mmap(memfd, 0, feMemSize, unix.PROT_READ|unix.PROT_WRITE, unix.MAP_SHARED)
	if err != nil {
		t.Fatal(err)
	}

	fe := &fakeFrontEnd{t: t, conn: feConn, memfd: memfd, mem: mem}
	t.Cleanup(func() {
		feConn.Close()
		unix.Munmap(mem)
		unix.Close(memfd)
		for _, f := range fe.kick {
			if f != nil {
				f.Close()
			}
		}
		for _, f := range fe.call {
			if f != nil {
				f.Close()
			}
		}
	})
	return fe, devConn
}

func (fe *fakeFrontEnd) send(req uint32, payload []byte, fds ...int) {
	fe.t.Helper()
	fe.sendFlags(req, flagVersion1, payload, fds...)
}

func (fe *fakeFrontEnd) sendFlags(req, flags uint32, payload []byte, fds ...int) {
	fe.t.Helper()
	hdr := make([]byte, hdrSize+len(payload))
	binary.LittleEndian.PutUint32(hdr[0:4], req)
	binary.LittleEndian.PutUint32(hdr[4:8], flags)
	binary.LittleEndian.PutUint32(hdr[8:12], uint32(len(payload)))
	copy(hdr[hdrSize:], payload)
	var oob []byte
	if len(fds) > 0 {
		oob = unix.UnixRights(fds...)
	}
	if _, _, err := fe.conn.WriteMsgUnix(hdr, oob, nil); err != nil {
		fe.t.Fatalf("send req %d: %v", req, err)
	}
}

// sendSync sends req with NEED_REPLY and returns the REPLY_ACK status.
// Requires protoFeatReplyAck to have been negotiated.
func (fe *fakeFrontEnd) sendSync(req uint32, payload []byte, fds ...int) uint64 {
	fe.t.Helper()
	fe.sendFlags(req, flagVersion1|flagNeedReply, payload, fds...)
	return binary.LittleEndian.Uint64(fe.recvReply(req))
}

func (fe *fakeFrontEnd) recvReply(req uint32) []byte {
	fe.t.Helper()
	fe.conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	hdr := make([]byte, hdrSize)
	for n := 0; n < hdrSize; {
		k, err := fe.conn.Read(hdr[n:])
		if err != nil {
			fe.t.Fatalf("recv reply hdr: %v", err)
		}
		n += k
	}
	if got := binary.LittleEndian.Uint32(hdr[0:4]); got != req {
		fe.t.Fatalf("reply for req %d, want %d", got, req)
	}
	size := binary.LittleEndian.Uint32(hdr[8:12])
	payload := make([]byte, size)
	for n := 0; n < int(size); {
		k, err := fe.conn.Read(payload[n:])
		if err != nil {
			fe.t.Fatalf("recv reply payload: %v", err)
		}
		n += k
	}
	return payload
}

func u32u32(a, b uint32) []byte {
	p := make([]byte, 8)
	binary.LittleEndian.PutUint32(p[0:4], a)
	binary.LittleEndian.PutUint32(p[4:8], b)
	return p
}

// setup runs the full handshake the way QEMU does.
func (fe *fakeFrontEnd) setup() {
	t := fe.t
	fe.send(reqGetFeatures, nil)
	feats := binary.LittleEndian.Uint64(fe.recvReply(reqGetFeatures))
	if feats&featVersion1 == 0 || feats&featProtocolFeatures == 0 {
		t.Fatalf("backend features %#x missing VERSION_1/PROTOCOL_FEATURES", feats)
	}
	fe.send(reqGetProtocolFeatures, nil)
	fe.recvReply(reqGetProtocolFeatures)
	fe.send(reqSetProtocolFeatures, u64Payload(protoFeatReplyAck))
	fe.send(reqSetFeatures, u64Payload(featVersion1|featNetMrgRxbuf|featProtocolFeatures))
	fe.send(reqSetOwner, nil)

	// One memory region covering the whole memfd. userspace_addr is our
	// own mapping base: the device translates vring addresses through it.
	base := uint64(uintptr(unsafe.Pointer(&fe.mem[0])))
	payload := make([]byte, 8+32)
	binary.LittleEndian.PutUint32(payload[0:4], 1)
	binary.LittleEndian.PutUint64(payload[8:16], feGPABase)  // guest_phys_addr
	binary.LittleEndian.PutUint64(payload[16:24], feMemSize) // size
	binary.LittleEndian.PutUint64(payload[24:32], base)      // userspace_addr
	binary.LittleEndian.PutUint64(payload[32:40], 0)         // mmap_offset
	fe.send(reqSetMemTable, payload, fe.memfd)

	for q := 0; q < nQueues; q++ {
		descOff, availOff, usedOff := ringOffsets(q)
		fe.send(reqSetVringNum, u32u32(uint32(q), feRingNum))
		fe.send(reqSetVringBase, u32u32(uint32(q), 0))

		addr := make([]byte, 40)
		binary.LittleEndian.PutUint32(addr[0:4], uint32(q))
		binary.LittleEndian.PutUint64(addr[8:16], base+descOff)
		binary.LittleEndian.PutUint64(addr[16:24], base+usedOff)
		binary.LittleEndian.PutUint64(addr[24:32], base+availOff)
		fe.send(reqSetVringAddr, addr)

		kickFD, err := unix.Eventfd(0, unix.EFD_CLOEXEC)
		if err != nil {
			t.Fatal(err)
		}
		callFD, err := unix.Eventfd(0, unix.EFD_CLOEXEC)
		if err != nil {
			t.Fatal(err)
		}
		// The device takes ownership of the transferred fd; keep dups
		// for ourselves.
		dupKick, _ := unix.Dup(kickFD)
		dupCall, _ := unix.Dup(callFD)
		unix.SetNonblock(dupCall, true)
		fe.kick[q] = os.NewFile(uintptr(dupKick), "fe-kick")
		fe.call[q] = os.NewFile(uintptr(dupCall), "fe-call")

		fe.send(reqSetVringCall, u64Payload(uint64(q)), callFD)
		fe.send(reqSetVringKick, u64Payload(uint64(q)), kickFD)
		unix.Close(kickFD)
		unix.Close(callFD)

		fe.send(reqSetVringEnable, u32u32(uint32(q), 1))
	}
}

// Driver-side ring helpers (the test is the guest driver).

func (fe *fakeFrontEnd) writeDesc(q int, i int, addr uint64, length uint32, flags, next uint16) {
	descOff, _, _ := ringOffsets(q)
	d := fe.mem[descOff+uint64(i)*descSize:]
	binary.LittleEndian.PutUint64(d[0:8], addr)
	binary.LittleEndian.PutUint32(d[8:12], length)
	binary.LittleEndian.PutUint16(d[12:14], flags)
	binary.LittleEndian.PutUint16(d[14:16], next)
}

// offerChains appends chain heads to the avail ring and bumps avail.idx.
func (fe *fakeFrontEnd) offerChains(q int, heads ...uint16) {
	_, availOff, _ := ringOffsets(q)
	avail := fe.mem[availOff:]
	idx := binary.LittleEndian.Uint16(avail[2:4])
	for n, h := range heads {
		slot := (uint32(idx) + uint32(n)) % feRingNum
		binary.LittleEndian.PutUint16(avail[4+2*slot:], h)
	}
	binary.LittleEndian.PutUint16(avail[2:4], idx+uint16(len(heads)))
}

func (fe *fakeFrontEnd) kickQueue(q int) {
	var one [8]byte
	one[0] = 1
	fe.kick[q].Write(one[:])
}

func (fe *fakeFrontEnd) usedIdx(q int) uint16 {
	_, _, usedOff := ringOffsets(q)
	return binary.LittleEndian.Uint16(fe.mem[usedOff+2:])
}

func (fe *fakeFrontEnd) usedElem(q int, slot uint32) (id, length uint32) {
	_, _, usedOff := ringOffsets(q)
	e := fe.mem[usedOff+4+8*uint64(slot%feRingNum):]
	return binary.LittleEndian.Uint32(e[0:4]), binary.LittleEndian.Uint32(e[4:8])
}

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatal("timeout waiting for " + what)
		}
		time.Sleep(2 * time.Millisecond)
	}
}

func testFrame(n int, fill byte) []byte {
	f := make([]byte, n)
	for i := range f {
		f[i] = fill
	}
	copy(f[0:6], []byte{0x02, 0, 0, 0, 0, 1})
	copy(f[6:12], []byte{0x02, 0, 0, 0, 0, 2})
	f[12], f[13] = 0x08, 0x00
	return f
}

func TestVhostUserTXAndRX(t *testing.T) {
	fe, devConn := newFakeFrontEnd(t)

	frames := make(chan []byte, 16)
	states := make(chan bool, 16)
	dev := NewNetDevice(devConn, false, Handlers{
		Frame: func(f []byte) { frames <- f },
		State: func(up bool) { states <- up },
	})
	defer dev.Close()

	fe.setup()
	waitFor(t, "dataplane up", func() bool {
		select {
		case up := <-states:
			return up
		default:
			return false
		}
	})

	// --- guest TX: hdr + frame in one descriptor ---
	want := testFrame(60, 0xab)
	buf := fe.mem[feBufBase:]
	for i := range buf[:virtioNetHdrSize] {
		buf[i] = 0
	}
	copy(buf[virtioNetHdrSize:], want)
	fe.writeDesc(txQueue, 0, feBufBase, uint32(virtioNetHdrSize+len(want)), 0, 0)
	fe.offerChains(txQueue, 0)
	fe.kickQueue(txQueue)

	select {
	case got := <-frames:
		if !bytes.Equal(got, want) {
			t.Fatalf("TX frame mismatch: got %d bytes", len(got))
		}
	case <-time.After(3 * time.Second):
		t.Fatal("no TX frame delivered")
	}
	waitFor(t, "TX used", func() bool { return fe.usedIdx(txQueue) == 1 })

	// --- device RX into a single ample buffer ---
	const rxBuf0 = feBufBase + 0x4000
	fe.writeDesc(rxQueue, 0, rxBuf0, 2048, descFlagWrite, 0)
	fe.offerChains(rxQueue, 0)

	rxFrame := testFrame(100, 0xcd)
	if !dev.WriteFrame(rxFrame) {
		t.Fatal("WriteFrame failed with buffers available")
	}
	if got := fe.usedIdx(rxQueue); got != 1 {
		t.Fatalf("RX used idx = %d, want 1", got)
	}
	id, length := fe.usedElem(rxQueue, 0)
	if id != 0 || int(length) != virtioNetHdrSize+len(rxFrame) {
		t.Fatalf("RX used elem id=%d len=%d", id, length)
	}
	got := fe.mem[rxBuf0 : rxBuf0+uint64(length)]
	if binary.LittleEndian.Uint16(got[10:12]) != 1 {
		t.Errorf("num_buffers = %d, want 1", binary.LittleEndian.Uint16(got[10:12]))
	}
	if !bytes.Equal(got[virtioNetHdrSize:], rxFrame) {
		t.Fatal("RX payload mismatch")
	}
	// The call eventfd must have fired.
	var ev [8]byte
	if _, err := fe.call[rxQueue].Read(ev[:]); err != nil {
		t.Fatalf("RX call eventfd not signalled: %v", err)
	}

	// --- mergeable RX: frame spans multiple small buffers ---
	const rxBuf1, rxBuf2, rxBuf3 = feBufBase + 0x6000, feBufBase + 0x6100, feBufBase + 0x6200
	fe.writeDesc(rxQueue, 1, rxBuf1, 64, descFlagWrite, 0)
	fe.writeDesc(rxQueue, 2, rxBuf2, 64, descFlagWrite, 0)
	fe.writeDesc(rxQueue, 3, rxBuf3, 64, descFlagWrite, 0)
	fe.offerChains(rxQueue, 1, 2, 3)

	big := testFrame(150, 0xef) // 12 + 150 = 162 bytes -> 3 x 64B buffers
	if !dev.WriteFrame(big) {
		t.Fatal("WriteFrame (merge) failed")
	}
	waitFor(t, "merged RX used", func() bool { return fe.usedIdx(rxQueue) == 4 })
	hdrBytes := fe.mem[rxBuf1 : rxBuf1+virtioNetHdrSize]
	numBuffers := binary.LittleEndian.Uint16(hdrBytes[10:12])
	if numBuffers != 3 {
		t.Fatalf("num_buffers = %d, want 3", numBuffers)
	}
	// Reassemble from the used elements.
	var rebuilt []byte
	bufAddrs := map[uint32]uint64{1: rxBuf1, 2: rxBuf2, 3: rxBuf3}
	for slot := uint32(1); slot < 4; slot++ {
		id, length := fe.usedElem(rxQueue, slot)
		rebuilt = append(rebuilt, fe.mem[bufAddrs[id]:bufAddrs[id]+uint64(length)]...)
	}
	if !bytes.Equal(rebuilt[virtioNetHdrSize:], big) {
		t.Fatal("merged RX payload mismatch")
	}

	// --- out of buffers: drop, not block ---
	if dev.WriteFrame(testFrame(60, 0x11)) {
		t.Fatal("WriteFrame succeeded with no buffers")
	}
}

// A kick consumed while the ring is paused (SET_VRING_ENABLE(0)) must not
// be lost: re-enabling the ring has to drain chains queued during the pause
// without waiting for the guest's next kick.
func TestVhostUserEnableResumesPendingTX(t *testing.T) {
	fe, devConn := newFakeFrontEnd(t)

	frames := make(chan []byte, 16)
	states := make(chan bool, 16)
	dev := NewNetDevice(devConn, false, Handlers{
		Frame: func(f []byte) { frames <- f },
		State: func(up bool) { states <- up },
	})
	defer dev.Close()

	fe.setup()
	waitFor(t, "dataplane up", func() bool {
		select {
		case up := <-states:
			return up
		default:
			return false
		}
	})

	// Pause the TX ring (synced via REPLY_ACK).
	if st := fe.sendSync(reqSetVringEnable, u32u32(txQueue, 0)); st != 0 {
		t.Fatalf("SET_VRING_ENABLE(0) status %d", st)
	}

	// Guest queues a frame and kicks while paused. Give the pump time to
	// consume (and discard) the kick.
	want := testFrame(60, 0x5a)
	buf := fe.mem[feBufBase:]
	for i := range buf[:virtioNetHdrSize] {
		buf[i] = 0
	}
	copy(buf[virtioNetHdrSize:], want)
	fe.writeDesc(txQueue, 0, feBufBase, uint32(virtioNetHdrSize+len(want)), 0, 0)
	fe.offerChains(txQueue, 0)
	fe.kickQueue(txQueue)
	time.Sleep(100 * time.Millisecond)

	select {
	case <-frames:
		t.Fatal("frame delivered while ring disabled")
	default:
	}

	// Re-enable: the pending chain must be drained without another kick.
	if st := fe.sendSync(reqSetVringEnable, u32u32(txQueue, 1)); st != 0 {
		t.Fatalf("SET_VRING_ENABLE(1) status %d", st)
	}
	select {
	case got := <-frames:
		if !bytes.Equal(got, want) {
			t.Fatalf("resumed TX frame mismatch: got %d bytes", len(got))
		}
	case <-time.After(3 * time.Second):
		t.Fatal("pending TX not drained after SET_VRING_ENABLE(1)")
	}
	waitFor(t, "TX used", func() bool { return fe.usedIdx(txQueue) == 1 })
}

// SET_MEM_TABLE may carry up to 32 regions (rust-vmm MAX_ATTACHED_FD_ENTRIES);
// all 32 fds must survive the SCM_RIGHTS receive path.
func TestVhostUserMemTable32Regions(t *testing.T) {
	fe, devConn := newFakeFrontEnd(t)

	dev := NewNetDevice(devConn, false, Handlers{})
	defer dev.Close()

	fe.send(reqGetFeatures, nil)
	fe.recvReply(reqGetFeatures)
	fe.send(reqGetProtocolFeatures, nil)
	fe.recvReply(reqGetProtocolFeatures)
	fe.send(reqSetProtocolFeatures, u64Payload(protoFeatReplyAck))
	fe.send(reqSetFeatures, u64Payload(featVersion1|featProtocolFeatures))

	const n = 32
	const regSize = 64 << 10 // 32 * 64KiB = 2MiB <= feMemSize
	base := uint64(uintptr(unsafe.Pointer(&fe.mem[0])))
	payload := make([]byte, 8+n*32)
	binary.LittleEndian.PutUint32(payload[0:4], n)
	fds := make([]int, n)
	for i := 0; i < n; i++ {
		off := uint64(i) * regSize
		p := payload[8+i*32:]
		binary.LittleEndian.PutUint64(p[0:8], feGPABase+off) // guest_phys_addr
		binary.LittleEndian.PutUint64(p[8:16], regSize)      // size
		binary.LittleEndian.PutUint64(p[16:24], base+off)    // userspace_addr
		binary.LittleEndian.PutUint64(p[24:32], off)         // mmap_offset
		fds[i] = fe.memfd
	}
	if st := fe.sendSync(reqSetMemTable, payload, fds...); st != 0 {
		t.Fatalf("SET_MEM_TABLE with 32 regions failed: status %d", st)
	}
}

// A GET request the device cannot answer must fail the session (EOF) rather
// than leave the front-end blocked waiting for a reply.
func TestVhostUserBadGetVringBaseClosesSession(t *testing.T) {
	fe, devConn := newFakeFrontEnd(t)

	dev := NewNetDevice(devConn, false, Handlers{})
	defer dev.Close()

	fe.send(reqGetVringBase, u32u32(99, 0))

	fe.conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	if _, err := fe.conn.Read(make([]byte, 1)); err == nil {
		t.Fatal("expected EOF after bad GET_VRING_BASE, got data")
	} else if os.IsTimeout(err) {
		t.Fatal("session left hanging after bad GET_VRING_BASE")
	}
}

func TestVhostUserSessionTeardown(t *testing.T) {
	fe, devConn := newFakeFrontEnd(t)

	states := make(chan bool, 16)
	dev := NewNetDevice(devConn, false, Handlers{
		State: func(up bool) { states <- up },
	})
	defer dev.Close()

	fe.setup()
	waitFor(t, "dataplane up", func() bool {
		select {
		case up := <-states:
			return up
		default:
			return false
		}
	})

	// GET_VRING_BASE stops the ring and reports the avail index.
	fe.send(reqGetVringBase, u32u32(txQueue, 0))
	reply := fe.recvReply(reqGetVringBase)
	if binary.LittleEndian.Uint32(reply[4:8]) != 0 {
		t.Errorf("vring base = %d, want 0", binary.LittleEndian.Uint32(reply[4:8]))
	}

	// Front-end disconnect ends the session.
	fe.conn.Close()
	waitFor(t, "dataplane down", func() bool {
		select {
		case up := <-states:
			return !up
		default:
			return false
		}
	})

	if dev.WriteFrame(testFrame(60, 0x22)) {
		t.Error("WriteFrame succeeded after teardown")
	}
}
