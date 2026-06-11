// Package vhostuser implements a vhost-user-net back-end (device side) in
// pure Go: the control protocol over a unix socket, guest-memory mapping,
// and device-side split-virtqueue processing. The front-end (QEMU/crosvm)
// owns the guest; we are the virtio-net device.
package vhostuser

import (
	"encoding/binary"
	"fmt"
	"net"

	"golang.org/x/sys/unix"
)

// Message types (vhost-user specification).
const (
	reqGetFeatures         = 1
	reqSetFeatures         = 2
	reqSetOwner            = 3
	reqResetOwner          = 4
	reqSetMemTable         = 5
	reqSetLogBase          = 6
	reqSetLogFD            = 7
	reqSetVringNum         = 8
	reqSetVringAddr        = 9
	reqSetVringBase        = 10
	reqGetVringBase        = 11
	reqSetVringKick        = 12
	reqSetVringCall        = 13
	reqSetVringErr         = 14
	reqGetProtocolFeatures = 15
	reqSetProtocolFeatures = 16
	reqGetQueueNum         = 17
	reqSetVringEnable      = 18
)

// Header flags.
const (
	flagVersion1  = 0x1
	flagVersionMa = 0x3
	flagReply     = 0x4
	flagNeedReply = 0x8
)

// Feature bits we deal in.
const (
	featNetMrgRxbuf      = 1 << 15 // VIRTIO_NET_F_MRG_RXBUF
	featVersion1         = 1 << 32 // VIRTIO_F_VERSION_1
	featProtocolFeatures = 1 << 30 // VHOST_USER_F_PROTOCOL_FEATURES
)

// Protocol feature bits.
const (
	protoFeatReplyAck = 1 << 3 // VHOST_USER_PROTOCOL_F_REPLY_ACK
)

// supportedFeatures is what we offer the front-end. No offloads, no
// event-idx, no indirect descriptors: the driver then never uses them.
const supportedFeatures = featVersion1 | featNetMrgRxbuf | featProtocolFeatures

const supportedProtocolFeatures = protoFeatReplyAck

const (
	hdrSize        = 12
	maxPayloadSize = 4096
	maxInFds       = 16

	// invalidFDFlag in a u64 vring-fd payload means "no fd attached".
	invalidFDFlag = 0x100
	vringIdxMask  = 0xff
)

type message struct {
	req     uint32
	flags   uint32
	payload []byte
	fds     []int
}

// readMsg reads one vhost-user message and any SCM_RIGHTS fds.
func readMsg(conn *net.UnixConn) (*message, error) {
	hdr := make([]byte, hdrSize)
	oob := make([]byte, unix.CmsgSpace(4*maxInFds))

	n, oobn, _, _, err := conn.ReadMsgUnix(hdr, oob)
	if err != nil {
		return nil, err
	}
	if n < hdrSize {
		// Header may arrive fragmented; finish it with plain reads.
		for n < hdrSize {
			m, err := conn.Read(hdr[n:])
			if err != nil {
				return nil, err
			}
			n += m
		}
	}

	m := &message{
		req:   binary.LittleEndian.Uint32(hdr[0:4]),
		flags: binary.LittleEndian.Uint32(hdr[4:8]),
	}
	size := binary.LittleEndian.Uint32(hdr[8:12])
	if size > maxPayloadSize {
		return nil, fmt.Errorf("payload size %d exceeds limit", size)
	}
	if size > 0 {
		m.payload = make([]byte, size)
		read := 0
		for read < int(size) {
			k, err := conn.Read(m.payload[read:])
			if err != nil {
				return nil, err
			}
			read += k
		}
	}

	if oobn > 0 {
		cmsgs, err := unix.ParseSocketControlMessage(oob[:oobn])
		if err != nil {
			return nil, fmt.Errorf("parse control message: %w", err)
		}
		for _, c := range cmsgs {
			fds, err := unix.ParseUnixRights(&c)
			if err != nil {
				continue
			}
			m.fds = append(m.fds, fds...)
		}
	}
	return m, nil
}

// writeReply sends a reply for req with the given payload.
func writeReply(conn *net.UnixConn, req uint32, payload []byte) error {
	buf := make([]byte, hdrSize+len(payload))
	binary.LittleEndian.PutUint32(buf[0:4], req)
	binary.LittleEndian.PutUint32(buf[4:8], flagVersion1|flagReply)
	binary.LittleEndian.PutUint32(buf[8:12], uint32(len(payload)))
	copy(buf[hdrSize:], payload)
	_, err := conn.Write(buf)
	return err
}

func u64Payload(v uint64) []byte {
	b := make([]byte, 8)
	binary.LittleEndian.PutUint64(b, v)
	return b
}

// vringStatePayload parses {index u32, num u32}.
func vringStatePayload(p []byte) (index, num uint32, err error) {
	if len(p) < 8 {
		return 0, 0, fmt.Errorf("short vring state payload")
	}
	return binary.LittleEndian.Uint32(p[0:4]), binary.LittleEndian.Uint32(p[4:8]), nil
}

// vringAddrPayload parses struct vhost_vring_addr.
type vringAddr struct {
	index uint32
	flags uint32
	desc  uint64
	used  uint64
	avail uint64
	log   uint64
}

func parseVringAddr(p []byte) (vringAddr, error) {
	if len(p) < 40 {
		return vringAddr{}, fmt.Errorf("short vring addr payload")
	}
	return vringAddr{
		index: binary.LittleEndian.Uint32(p[0:4]),
		flags: binary.LittleEndian.Uint32(p[4:8]),
		desc:  binary.LittleEndian.Uint64(p[8:16]),
		used:  binary.LittleEndian.Uint64(p[16:24]),
		avail: binary.LittleEndian.Uint64(p[24:32]),
		log:   binary.LittleEndian.Uint64(p[32:40]),
	}, nil
}

func closeFds(fds []int) {
	for _, fd := range fds {
		unix.Close(fd)
	}
}
