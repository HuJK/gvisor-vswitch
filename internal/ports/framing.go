package ports

import (
	"bufio"
	"encoding/binary"
	"fmt"
	"io"
	"net"
)

// maxFrameSize bounds a single ethernet frame on the wire. Generous enough
// for jumbo frames; small enough that a corrupt length prefix cannot ask us
// to allocate gigabytes.
const maxFrameSize = 65535

// frameIO reads and writes whole ethernet frames over some transport.
// ReadFrame returns a freshly allocated buffer each call (the switch takes
// ownership of delivered frames).
type frameIO interface {
	ReadFrame() ([]byte, error)
	WriteFrame(frame []byte) error
	Close() error
}

// streamIO frames a byte stream with the QEMU -netdev socket/stream format:
// 4-byte big-endian frame length, then the frame.
type streamIO struct {
	conn net.Conn
	r    *bufio.Reader
}

func newStreamIO(conn net.Conn) *streamIO {
	return &streamIO{conn: conn, r: bufio.NewReaderSize(conn, 64*1024)}
}

func (s *streamIO) ReadFrame() ([]byte, error) {
	var hdr [4]byte
	if _, err := io.ReadFull(s.r, hdr[:]); err != nil {
		return nil, err
	}
	n := binary.BigEndian.Uint32(hdr[:])
	if n == 0 || n > maxFrameSize {
		return nil, fmt.Errorf("bad frame length %d", n)
	}
	buf := make([]byte, n)
	if _, err := io.ReadFull(s.r, buf); err != nil {
		return nil, err
	}
	return buf, nil
}

func (s *streamIO) WriteFrame(frame []byte) error {
	// Single Write so frames are never interleaved should writers race.
	buf := make([]byte, 4+len(frame))
	binary.BigEndian.PutUint32(buf[:4], uint32(len(frame)))
	copy(buf[4:], frame)
	_, err := s.conn.Write(buf)
	return err
}

func (s *streamIO) Close() error { return s.conn.Close() }

// dgramIO carries one frame per datagram over a connected datagram socket.
// ReadFrame is called from a single goroutine (the pump RX loop), so the
// scratch buffer needs no locking; frames are copied out right-sized so the
// 64K scratch is never pinned by queued frames.
type dgramIO struct {
	conn    net.Conn
	scratch [maxFrameSize + 1]byte
}

func (d *dgramIO) ReadFrame() ([]byte, error) {
	n, err := d.conn.Read(d.scratch[:])
	if err != nil {
		return nil, err
	}
	frame := make([]byte, n)
	copy(frame, d.scratch[:n])
	return frame, nil
}

func (d *dgramIO) WriteFrame(frame []byte) error {
	_, err := d.conn.Write(frame)
	return err
}

func (d *dgramIO) Close() error { return d.conn.Close() }
