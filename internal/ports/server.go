package ports

import (
	"fmt"
	"net"
	"sort"
	"strings"
	"sync"

	"github.com/mdlayher/vsock"

	"github.com/HuJK/gvisor-vswitch/internal/switchcore"
)

// ServerConfig describes a server-mode (listening) port.
type ServerConfig struct {
	ID        string
	Transport string // tcp | unix | vsock (stream) / udp | unixgram | vsock-dgram
	Listen    string
	Mode      ReplacingMode
	// Attrs are the switchport attributes; multiplex subports inherit them.
	Attrs switchcore.PortAttrs
}

// NewServer starts listening per cfg. For stream transports it accepts
// connections according to the replacing mode; for datagram transports it
// tracks the current peer address.
func NewServer(sw *switchcore.Switch, cfg ServerConfig) (ManagedPort, error) {
	if err := validateTransport(cfg.Transport); err != nil {
		return nil, err
	}
	switch cfg.Mode {
	case ModeReplace, ModeOccupy:
	case ModeMultiplex:
		if isDgramTransport(cfg.Transport) {
			return nil, fmt.Errorf("multiplex mode is not supported on datagram transports")
		}
	case "":
		cfg.Mode = ModeReplace
	default:
		return nil, fmt.Errorf("unknown replacing mode %q", cfg.Mode)
	}

	if isDgramTransport(cfg.Transport) {
		return newDgramServer(sw, cfg)
	}
	return newStreamServer(sw, cfg)
}

// --- stream server ---

type streamServer struct {
	id   string
	sw   *switchcore.Switch
	mode ReplacingMode
	ln   net.Listener

	mu      sync.Mutex
	attrs   switchcore.PortAttrs
	pump    *pump // replace/occupy: the adopted connection
	peer    string
	subs    map[string]*subPort // multiplex: subport ID -> port
	anonIDs map[int]bool        // multiplex: @anonymous-N allocator
	closed  bool
}

func newStreamServer(sw *switchcore.Switch, cfg ServerConfig) (ManagedPort, error) {
	ln, err := listenStream(cfg.Transport, cfg.Listen)
	if err != nil {
		return nil, fmt.Errorf("listen %s %s: %w", cfg.Transport, cfg.Listen, err)
	}
	s := &streamServer{
		id:      cfg.ID,
		sw:      sw,
		mode:    cfg.Mode,
		ln:      ln,
		attrs:   cfg.Attrs,
		subs:    make(map[string]*subPort),
		anonIDs: make(map[int]bool),
	}
	go s.acceptLoop()
	return s, nil
}

func (s *streamServer) acceptLoop() {
	for {
		conn, err := s.ln.Accept()
		if err != nil {
			return // listener closed
		}
		switch s.mode {
		case ModeReplace:
			s.adopt(conn, true)
		case ModeOccupy:
			s.adopt(conn, false)
		case ModeMultiplex:
			s.addSub(conn)
		}
	}
}

// adopt installs conn as the port's connection. With kickOld the previous
// connection is closed first; otherwise conn is rejected while one is live.
func (s *streamServer) adopt(conn net.Conn, kickOld bool) {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		conn.Close()
		return
	}
	if s.pump != nil {
		if !kickOld {
			s.mu.Unlock()
			conn.Close()
			return
		}
		old := s.pump
		s.pump = nil
		s.mu.Unlock()
		old.stop()
		s.mu.Lock()
		if s.closed || s.pump != nil {
			// Lost a race with Close or another accept.
			s.mu.Unlock()
			conn.Close()
			return
		}
	}
	pmp := newPump(s.sw.Ref(s.id), newStreamIO(conn), func() {
		offline := false
		s.mu.Lock()
		if s.pump != nil && s.pump.stopped() {
			s.pump = nil
			s.peer = ""
			offline = true
		}
		s.mu.Unlock()
		if offline {
			s.sw.NotifyDown(s.id)
		}
	})
	s.pump = pmp
	s.peer = peerString(conn)
	s.mu.Unlock()
	pmp.start()
}

// addSub registers conn as its own switchport `<id>@<client>`.
func (s *streamServer) addSub(conn net.Conn) {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		conn.Close()
		return
	}
	peer := peerString(conn)
	anonID := -1
	if peer == "" {
		anonID = s.allocAnonLocked()
		peer = fmt.Sprintf("anonymous-%d", anonID)
	}
	subID := s.id + "@" + peer
	if _, dup := s.subs[subID]; dup {
		// Same peer string twice (shouldn't happen for live conns);
		// refuse the newcomer.
		if anonID >= 0 {
			delete(s.anonIDs, anonID)
		}
		s.mu.Unlock()
		conn.Close()
		return
	}
	sub := &subPort{id: subID}
	sub.pump = newPump(s.sw.Ref(subID), newStreamIO(conn), func() {
		s.mu.Lock()
		delete(s.subs, subID)
		if anonID >= 0 {
			delete(s.anonIDs, anonID)
		}
		s.mu.Unlock()
		s.sw.RemovePort(subID)
	})
	s.subs[subID] = sub
	attrs := s.attrs
	s.mu.Unlock()

	if err := s.sw.AddPort(sub, attrs); err != nil {
		s.mu.Lock()
		delete(s.subs, subID)
		if anonID >= 0 {
			delete(s.anonIDs, anonID)
		}
		s.mu.Unlock()
		conn.Close()
		return
	}
	sub.pump.start()
}

func (s *streamServer) allocAnonLocked() int {
	for i := 0; ; i++ {
		if !s.anonIDs[i] {
			s.anonIDs[i] = true
			return i
		}
	}
}

func (s *streamServer) ID() string { return s.id }

func (s *streamServer) Send(_ switchcore.Meta, frame []byte) bool {
	// Multiplex subports receive frames themselves; the parent port only
	// carries traffic in replace/occupy modes.
	s.mu.Lock()
	pmp := s.pump
	s.mu.Unlock()
	if pmp == nil {
		return false
	}
	return pmp.send(frame)
}

func (s *streamServer) Close() error {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil
	}
	s.closed = true
	pmp := s.pump
	s.pump = nil
	subs := make([]*subPort, 0, len(s.subs))
	for _, sub := range s.subs {
		subs = append(subs, sub)
	}
	s.mu.Unlock()

	s.ln.Close()
	if pmp != nil {
		pmp.stop()
	}
	for _, sub := range subs {
		sub.pump.stop() // onExit removes it from the switch
	}
	return nil
}

func (s *streamServer) Status() Status {
	s.mu.Lock()
	defer s.mu.Unlock()
	st := Status{Peer: s.peer}
	if s.mode == ModeMultiplex {
		st.Online = len(s.subs) > 0
		st.Connections = make([]string, 0, len(s.subs))
		for id := range s.subs {
			st.Connections = append(st.Connections, id)
		}
		sort.Strings(st.Connections)
	} else {
		st.Online = s.pump != nil
	}
	return st
}

func (s *streamServer) UpdateSubAttrs(attrs switchcore.PortAttrs) {
	s.mu.Lock()
	s.attrs = attrs
	ids := make([]string, 0, len(s.subs))
	for id := range s.subs {
		ids = append(ids, id)
	}
	s.mu.Unlock()
	for _, id := range ids {
		s.sw.UpdatePortAttrs(id, attrs)
	}
}

// subPort is one multiplexed client connection acting as a switchport.
type subPort struct {
	id   string
	pump *pump
}

func (p *subPort) ID() string { return p.id }
func (p *subPort) Send(_ switchcore.Meta, frame []byte) bool {
	return p.pump.send(frame)
}
func (p *subPort) Close() error {
	p.pump.stop()
	return nil
}

// peerString renders a client address for multiplex subport naming:
// tcp -> ip:port, vsock -> cid:port, unix -> socket name or "" when the
// client socket is unbound (anonymous).
func peerString(conn net.Conn) string {
	addr := conn.RemoteAddr()
	if addr == nil {
		return ""
	}
	if va, ok := addr.(*vsock.Addr); ok {
		return fmt.Sprintf("%d:%d", va.ContextID, va.Port)
	}
	s := addr.String()
	if addr.Network() == "unix" {
		s = strings.TrimSpace(s)
		if s == "" || s == "@" {
			return ""
		}
	}
	return s
}

// --- datagram server ---

// dgramServer is a connectionless port: the peer is whoever sent the last
// acceptable datagram. replace updates the peer on any new source address;
// occupy sticks with the first source until the port is deleted.
type dgramServer struct {
	id   string
	sw   *switchcore.Switch
	ref  *switchcore.PortRef
	mode ReplacingMode
	pc   net.PacketConn

	mu     sync.Mutex
	peer   net.Addr
	closed bool
}

func newDgramServer(sw *switchcore.Switch, cfg ServerConfig) (ManagedPort, error) {
	pc, err := listenPacket(cfg.Transport, cfg.Listen)
	if err != nil {
		return nil, fmt.Errorf("listen %s %s: %w", cfg.Transport, cfg.Listen, err)
	}
	s := &dgramServer{id: cfg.ID, sw: sw, ref: sw.Ref(cfg.ID), mode: cfg.Mode, pc: pc}
	go s.rxLoop()
	return s, nil
}

func (s *dgramServer) rxLoop() {
	buf := make([]byte, maxFrameSize+1)
	for {
		n, addr, err := s.pc.ReadFrom(buf)
		if err != nil {
			return // closed
		}
		s.mu.Lock()
		switch {
		case s.peer == nil:
			s.peer = addr
		case addr.String() != s.peer.String():
			if s.mode == ModeReplace {
				s.peer = addr
			} else { // occupy: ignore datagrams from other sources
				s.mu.Unlock()
				continue
			}
		}
		s.mu.Unlock()

		frame := make([]byte, n)
		copy(frame, buf[:n])
		s.ref.Deliver(frame)
	}
}

func (s *dgramServer) ID() string { return s.id }

func (s *dgramServer) Send(_ switchcore.Meta, frame []byte) bool {
	s.mu.Lock()
	peer := s.peer
	s.mu.Unlock()
	if peer == nil {
		return false
	}
	_, err := s.pc.WriteTo(frame, peer)
	return err == nil
}

func (s *dgramServer) Close() error {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil
	}
	s.closed = true
	s.mu.Unlock()
	return s.pc.Close()
}

func (s *dgramServer) Status() Status {
	s.mu.Lock()
	defer s.mu.Unlock()
	st := Status{Online: s.peer != nil}
	if s.peer != nil {
		st.Peer = s.peer.String()
	}
	return st
}
