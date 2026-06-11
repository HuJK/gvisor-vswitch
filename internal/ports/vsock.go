package ports

import (
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/mdlayher/vsock"
	"golang.org/x/sys/unix"
)

// vsock addresses are "cid:port"; listen addresses may omit the cid
// (":port" or "port") to bind VMADDR_CID_ANY.
//
// Stream uses AF_VSOCK SOCK_STREAM via mdlayher/vsock. Datagram is
// best-effort raw AF_VSOCK SOCK_DGRAM: mainline virtio-vsock does not
// support it (only VMCI/Hyper-V transports do), so socket creation may fail
// with a clear error.

func parseVsockAddr(s string, cidOptional bool) (cid, port uint32, err error) {
	cidStr, portStr, found := strings.Cut(s, ":")
	if !found {
		cidStr, portStr = "", s
	}
	if cidStr == "" {
		if !cidOptional {
			return 0, 0, fmt.Errorf("vsock address %q needs cid:port", s)
		}
		cid = unix.VMADDR_CID_ANY
	} else {
		c, err := strconv.ParseUint(cidStr, 10, 32)
		if err != nil {
			return 0, 0, fmt.Errorf("bad vsock cid %q: %w", cidStr, err)
		}
		cid = uint32(c)
	}
	p, err := strconv.ParseUint(portStr, 10, 32)
	if err != nil {
		return 0, 0, fmt.Errorf("bad vsock port %q: %w", portStr, err)
	}
	return cid, uint32(p), nil
}

func dialVsockStream(local, remote string) (net.Conn, error) {
	if local != "" {
		return nil, fmt.Errorf("vsock does not support a local bind address")
	}
	cid, port, err := parseVsockAddr(remote, false)
	if err != nil {
		return nil, err
	}
	return vsock.Dial(cid, port, nil)
}

func listenVsockStream(addr string) (net.Listener, error) {
	cid, port, err := parseVsockAddr(addr, true)
	if err != nil {
		return nil, err
	}
	if cid != unix.VMADDR_CID_ANY {
		return vsock.ListenContextID(cid, port, nil)
	}
	return vsock.Listen(port, nil)
}

// --- datagram (best effort) ---

// vsockDgram is a minimal net.Conn / net.PacketConn over AF_VSOCK
// SOCK_DGRAM.
type vsockDgram struct {
	fd    int
	local *vsockAddr
	peer  *vsockAddr // connected mode
}

type vsockAddr struct {
	cid, port uint32
}

func (a *vsockAddr) Network() string { return "vsock-dgram" }
func (a *vsockAddr) String() string  { return fmt.Sprintf("%d:%d", a.cid, a.port) }

func newVsockDgramSocket(local string) (*vsockDgram, error) {
	fd, err := unix.Socket(unix.AF_VSOCK, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return nil, fmt.Errorf("vsock SOCK_DGRAM unsupported on this kernel/transport: %w", err)
	}
	d := &vsockDgram{fd: fd, local: &vsockAddr{cid: unix.VMADDR_CID_ANY, port: unix.VMADDR_PORT_ANY}}
	if local != "" {
		cid, port, err := parseVsockAddr(local, true)
		if err != nil {
			unix.Close(fd)
			return nil, err
		}
		if err := unix.Bind(fd, &unix.SockaddrVM{CID: cid, Port: port}); err != nil {
			unix.Close(fd)
			return nil, fmt.Errorf("vsock bind %s: %w", local, err)
		}
		d.local = &vsockAddr{cid: cid, port: port}
	}
	return d, nil
}

func dialVsockDgram(local, remote string) (net.Conn, error) {
	cid, port, err := parseVsockAddr(remote, false)
	if err != nil {
		return nil, err
	}
	d, err := newVsockDgramSocket(local)
	if err != nil {
		return nil, err
	}
	if err := unix.Connect(d.fd, &unix.SockaddrVM{CID: cid, Port: port}); err != nil {
		d.Close()
		return nil, fmt.Errorf("vsock connect %s: %w", remote, err)
	}
	d.peer = &vsockAddr{cid: cid, port: port}
	return d, nil
}

func listenVsockDgram(addr string) (net.PacketConn, error) {
	if addr == "" {
		return nil, fmt.Errorf("vsock-dgram listen address required")
	}
	return newVsockDgramSocket(addr)
}

// net.Conn (connected mode)

func (d *vsockDgram) Read(b []byte) (int, error) {
	n, _, err := unix.Recvfrom(d.fd, b, 0)
	return n, err
}

func (d *vsockDgram) Write(b []byte) (int, error) {
	err := unix.Send(d.fd, b, 0)
	if err != nil {
		return 0, err
	}
	return len(b), nil
}

// net.PacketConn

func (d *vsockDgram) ReadFrom(b []byte) (int, net.Addr, error) {
	n, sa, err := unix.Recvfrom(d.fd, b, 0)
	if err != nil {
		return n, nil, err
	}
	if vm, ok := sa.(*unix.SockaddrVM); ok {
		return n, &vsockAddr{cid: vm.CID, port: vm.Port}, nil
	}
	return n, d.local, nil
}

func (d *vsockDgram) WriteTo(b []byte, addr net.Addr) (int, error) {
	va, ok := addr.(*vsockAddr)
	if !ok {
		return 0, fmt.Errorf("not a vsock address: %v", addr)
	}
	err := unix.Sendto(d.fd, b, 0, &unix.SockaddrVM{CID: va.cid, Port: va.port})
	if err != nil {
		return 0, err
	}
	return len(b), nil
}

func (d *vsockDgram) Close() error        { return unix.Close(d.fd) }
func (d *vsockDgram) LocalAddr() net.Addr { return d.local }
func (d *vsockDgram) RemoteAddr() net.Addr {
	if d.peer != nil {
		return d.peer
	}
	return nil
}
func (d *vsockDgram) SetDeadline(t time.Time) error      { return nil }
func (d *vsockDgram) SetReadDeadline(t time.Time) error  { return nil }
func (d *vsockDgram) SetWriteDeadline(t time.Time) error { return nil }
