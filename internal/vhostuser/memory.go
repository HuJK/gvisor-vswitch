package vhostuser

import (
	"encoding/binary"
	"fmt"

	"golang.org/x/sys/unix"
)

// memRegion is one mapped guest-memory region. Descriptor buffers are
// addressed by guest-physical address (GPA); the vring addresses arrive as
// front-end (QEMU) virtual addresses (UVA). Both translate through here.
type memRegion struct {
	gpa  uint64 // guest physical base
	size uint64
	uva  uint64 // front-end userspace base

	mapped []byte // our mapping, adjusted so mapped[0] == gpa base
	raw    []byte // raw mmap (page-aligned) for munmap
}

type memTable struct {
	regions []memRegion
}

// parseMemTable maps the regions of a SET_MEM_TABLE message. Each region
// comes with one fd, in order.
func parseMemTable(payload []byte, fds []int) (*memTable, error) {
	if len(payload) < 8 {
		return nil, fmt.Errorf("short mem table payload")
	}
	n := binary.LittleEndian.Uint32(payload[0:4])
	if n == 0 || n > 32 {
		return nil, fmt.Errorf("bad region count %d", n)
	}
	if len(fds) < int(n) {
		return nil, fmt.Errorf("mem table has %d regions but %d fds", n, len(fds))
	}
	if len(payload) < 8+int(n)*32 {
		return nil, fmt.Errorf("short mem table payload for %d regions", n)
	}

	t := &memTable{}
	pageMask := uint64(unix.Getpagesize() - 1)
	for i := 0; i < int(n); i++ {
		p := payload[8+i*32:]
		r := memRegion{
			gpa:  binary.LittleEndian.Uint64(p[0:8]),
			size: binary.LittleEndian.Uint64(p[8:16]),
			uva:  binary.LittleEndian.Uint64(p[16:24]),
		}
		mmapOffset := binary.LittleEndian.Uint64(p[24:32])

		// mmap requires a page-aligned file offset; compensate by
		// over-mapping from the aligned-down offset.
		pad := mmapOffset & pageMask
		raw, err := unix.Mmap(fds[i], int64(mmapOffset-pad), int(r.size+pad),
			unix.PROT_READ|unix.PROT_WRITE, unix.MAP_SHARED)
		if err != nil {
			t.close()
			return nil, fmt.Errorf("mmap region %d (size %d): %w", i, r.size, err)
		}
		r.raw = raw
		r.mapped = raw[pad : pad+r.size]
		t.regions = append(t.regions, r)
	}
	return t, nil
}

func (t *memTable) close() {
	for _, r := range t.regions {
		unix.Munmap(r.raw)
	}
	t.regions = nil
}

// gpaSlice resolves [gpa, gpa+size) to our mapping. The range must not
// cross a region boundary. Descriptor contents are guest-controlled: every
// access goes through this bounds check.
func (t *memTable) gpaSlice(gpa, size uint64) ([]byte, error) {
	if size == 0 {
		return nil, fmt.Errorf("zero-length gpa range")
	}
	for i := range t.regions {
		r := &t.regions[i]
		if gpa >= r.gpa && gpa-r.gpa+size <= r.size {
			off := gpa - r.gpa
			return r.mapped[off : off+size : off+size], nil
		}
	}
	return nil, fmt.Errorf("gpa range [%#x, +%d) not in any region", gpa, size)
}

// uvaSlice resolves a front-end virtual address range (vring addresses).
func (t *memTable) uvaSlice(uva, size uint64) ([]byte, error) {
	if size == 0 {
		return nil, fmt.Errorf("zero-length uva range")
	}
	for i := range t.regions {
		r := &t.regions[i]
		if uva >= r.uva && uva-r.uva+size <= r.size {
			off := uva - r.uva
			return r.mapped[off : off+size : off+size], nil
		}
	}
	return nil, fmt.Errorf("uva range [%#x, +%d) not in any region", uva, size)
}
