package vhostuser

import (
	"encoding/binary"
	"fmt"
	"os"
	"sync/atomic"
	"unsafe"
)

// Device-side split virtqueue (virtio 1.x "split" layout). We consume the
// driver's available ring and produce into the used ring; both live in
// guest memory mapped by memTable.

const (
	descSize = 16

	descFlagNext     = 1
	descFlagWrite    = 2
	descFlagIndirect = 4

	availFlagNoInterrupt = 1

	// virtioNetHdrSize: with VIRTIO_F_VERSION_1 the virtio-net header is
	// always 12 bytes (incl. num_buffers).
	virtioNetHdrSize = 12

	// maxChainLen bounds descriptor-chain walks; the chain "next" fields
	// are guest-controlled and could otherwise loop forever.
	maxChainLen = 256
)

type vring struct {
	num uint32

	desc  []byte // num * 16
	avail []byte // 4 + num*2
	used  []byte // 4 + num*8

	lastAvail uint16 // next avail index to consume
	usedIdx   uint16 // next used index to produce

	kick *os.File
	call *os.File

	enabled bool
	// started gates all dataplane activity (pausable via
	// SET_VRING_ENABLE); pumpRunning tracks whether a TX pump goroutine
	// is alive for this ring's kick fd.
	started     bool
	pumpRunning bool
}

// atomicLoadU32 / atomicStoreU32 operate on the flags+idx word at the head
// of the avail/used rings. Go has no 16-bit atomics, but flags and idx
// share an aligned u32 (LE: flags = low half, idx = high half), which gives
// us acquire/release on idx for free.
func atomicLoadU32(b []byte) uint32 {
	return atomic.LoadUint32((*uint32)(unsafe.Pointer(&b[0])))
}

func atomicStoreU32(b []byte, v uint32) {
	atomic.StoreUint32((*uint32)(unsafe.Pointer(&b[0])), v)
}

// availIdx returns the driver's current avail index (acquire).
func (v *vring) availIdx() uint16 {
	return uint16(atomicLoadU32(v.avail) >> 16)
}

// availNoInterrupt reports whether the driver asked to suppress used-ring
// notifications.
func (v *vring) availNoInterrupt() bool {
	return uint16(atomicLoadU32(v.avail))&availFlagNoInterrupt != 0
}

// availEntry returns the descriptor-chain head queued at avail slot i.
func (v *vring) availEntry(i uint16) uint16 {
	off := 4 + 2*(uint32(i)%v.num)
	return binary.LittleEndian.Uint16(v.avail[off:])
}

// publishUsed writes used elements and advances the used index (release).
// All elements must already be written via setUsedElem.
func (v *vring) publishUsed(count uint16) {
	v.usedIdx += count
	atomicStoreU32(v.used, uint32(v.usedIdx)<<16) // used.flags stays 0
}

// setUsedElem fills the used-ring element at logical index v.usedIdx+slot.
func (v *vring) setUsedElem(slot uint16, head uint16, written uint32) {
	off := 4 + 8*((uint32(v.usedIdx)+uint32(slot))%v.num)
	binary.LittleEndian.PutUint32(v.used[off:], uint32(head))
	binary.LittleEndian.PutUint32(v.used[off+4:], written)
}

// notify signals the driver via the call eventfd unless suppressed.
func (v *vring) notify() {
	if v.call == nil || v.availNoInterrupt() {
		return
	}
	var one [8]byte
	one[0] = 1
	v.call.Write(one[:])
}

// descriptor is one entry of the descriptor table.
type descriptor struct {
	addr  uint64
	len   uint32
	flags uint16
	next  uint16
}

func (v *vring) descAt(i uint16) (descriptor, error) {
	if uint32(i) >= v.num {
		return descriptor{}, fmt.Errorf("descriptor index %d out of range", i)
	}
	off := uint32(i) * descSize
	d := v.desc[off : off+descSize]
	return descriptor{
		addr:  binary.LittleEndian.Uint64(d[0:8]),
		len:   binary.LittleEndian.Uint32(d[8:12]),
		flags: binary.LittleEndian.Uint16(d[12:14]),
		next:  binary.LittleEndian.Uint16(d[14:16]),
	}, nil
}

// chain is a resolved descriptor chain: the guest-memory segments it
// references, split into device-readable and device-writable parts.
type chain struct {
	head     uint16
	readable [][]byte
	writable [][]byte
}

// resolveChain walks the chain starting at head and bounds-checks every
// segment against the memory table.
func (v *vring) resolveChain(mem *memTable, head uint16) (chain, error) {
	c := chain{head: head}
	idx := head
	for i := 0; ; i++ {
		if i >= maxChainLen {
			return c, fmt.Errorf("descriptor chain too long")
		}
		d, err := v.descAt(idx)
		if err != nil {
			return c, err
		}
		if d.flags&descFlagIndirect != 0 {
			// Not negotiated; a conforming driver never sets this.
			return c, fmt.Errorf("unexpected indirect descriptor")
		}
		seg, err := mem.gpaSlice(d.addr, uint64(d.len))
		if err != nil {
			return c, err
		}
		if d.flags&descFlagWrite != 0 {
			c.writable = append(c.writable, seg)
		} else {
			if len(c.writable) > 0 {
				return c, fmt.Errorf("readable descriptor after writable")
			}
			c.readable = append(c.readable, seg)
		}
		if d.flags&descFlagNext == 0 {
			return c, nil
		}
		idx = d.next
	}
}

// popAvail consumes the next available chain head, or ok=false when the
// ring is empty.
func (v *vring) popAvail() (uint16, bool) {
	if v.lastAvail == v.availIdx() {
		return 0, false
	}
	head := v.availEntry(v.lastAvail)
	v.lastAvail++
	return head, true
}
