package ports

import (
	"errors"
	"fmt"
	"net"
	"os"
	"syscall"
	"time"
)

const dialTimeout = 10 * time.Second

// dialStream connects a stream transport. local, when set, is the bind
// address (tcp ip:port, unix path).
func dialStream(transport, local, remote string) (net.Conn, error) {
	switch transport {
	case "tcp":
		d := net.Dialer{Timeout: dialTimeout}
		if local != "" {
			laddr, err := net.ResolveTCPAddr("tcp", local)
			if err != nil {
				return nil, fmt.Errorf("bad local address: %w", err)
			}
			d.LocalAddr = laddr
		}
		return d.Dial("tcp", remote)
	case "unix":
		var laddr *net.UnixAddr
		if local != "" {
			laddr = &net.UnixAddr{Name: local, Net: "unix"}
		}
		return net.DialUnix("unix", laddr, &net.UnixAddr{Name: remote, Net: "unix"})
	case "vsock":
		return dialVsockStream(local, remote)
	}
	return nil, fmt.Errorf("transport %q is not a stream transport", transport)
}

// dialDgram connects a datagram transport. unixgram requires a local bind:
// an unbound unix datagram socket has no address for the peer to reply to.
func dialDgram(transport, local, remote string) (net.Conn, error) {
	switch transport {
	case "udp":
		raddr, err := net.ResolveUDPAddr("udp", remote)
		if err != nil {
			return nil, fmt.Errorf("bad remote address: %w", err)
		}
		var laddr *net.UDPAddr
		if local != "" {
			if laddr, err = net.ResolveUDPAddr("udp", local); err != nil {
				return nil, fmt.Errorf("bad local address: %w", err)
			}
		}
		return net.DialUDP("udp", laddr, raddr)
	case "unixgram":
		if local == "" {
			return nil, fmt.Errorf("unixgram client requires a local bind path to receive frames")
		}
		removeStaleSocket(local)
		return net.DialUnix("unixgram",
			&net.UnixAddr{Name: local, Net: "unixgram"},
			&net.UnixAddr{Name: remote, Net: "unixgram"})
	case "vsock-dgram":
		return dialVsockDgram(local, remote)
	}
	return nil, fmt.Errorf("transport %q is not a datagram transport", transport)
}

func listenStream(transport, addr string) (net.Listener, error) {
	switch transport {
	case "tcp":
		return net.Listen("tcp", addr)
	case "unix":
		ln, err := net.Listen("unix", addr)
		if err != nil && isAddrInUse(err) && unixSocketIsStale(addr) {
			os.Remove(addr)
			ln, err = net.Listen("unix", addr)
		}
		return ln, err
	case "vsock":
		return listenVsockStream(addr)
	}
	return nil, fmt.Errorf("transport %q is not a stream transport", transport)
}

func listenPacket(transport, addr string) (net.PacketConn, error) {
	switch transport {
	case "udp":
		return net.ListenPacket("udp", addr)
	case "unixgram":
		pc, err := net.ListenPacket("unixgram", addr)
		if err != nil && isAddrInUse(err) {
			// No reliable liveness probe for unix datagram sockets;
			// assume a leftover from a previous run.
			os.Remove(addr)
			pc, err = net.ListenPacket("unixgram", addr)
		}
		return pc, err
	case "vsock-dgram":
		return listenVsockDgram(addr)
	}
	return nil, fmt.Errorf("transport %q is not a datagram transport", transport)
}

func isAddrInUse(err error) bool {
	return errors.Is(err, syscall.EADDRINUSE)
}

// unixSocketIsStale reports whether a unix stream socket path exists but
// nothing accepts on it.
func unixSocketIsStale(path string) bool {
	conn, err := net.DialTimeout("unix", path, time.Second)
	if err != nil {
		return true
	}
	conn.Close()
	return false
}

func removeStaleSocket(path string) {
	if fi, err := os.Stat(path); err == nil && fi.Mode()&os.ModeSocket != 0 {
		os.Remove(path)
	}
}
