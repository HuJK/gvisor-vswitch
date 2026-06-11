package slirpnetstack

// This file is maintained in the gvisor-vswitch repository (_overlay/) and
// copied into the slirpnetstack checkout by sync-slirpnetstack.sh. It lives in
// package slirpnetstack so it can reach package-internal symbols, and exports
// just enough surface for the vswitch gateway:
//
//   - constructors for the lowercase types the gateway wires together
//     (localAddrs, hostFilterEndpoint, State)
//   - DynFwdTable + routing handlers: same logic as routing.go, but the
//     remote-forward tables are mutex-protected so rules can be added and
//     removed at runtime (upstream builds its maps once at startup)
//   - FwdAddr construction/accessors for the REST API

import (
	"fmt"
	"net"
	"sync"
	"time"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
	"gvisor.dev/gvisor/pkg/waiter"
)

// LocalAddrs is the set of addresses the gateway answers ARP/NDP for.
type LocalAddrs = localAddrs

func NewLocalAddrs(addrs ...tcpip.Address) *LocalAddrs {
	return newLocalAddrs(addrs...)
}

func LocalAddrsAdd(l *LocalAddrs, a tcpip.Address) {
	l.add(a)
}

// Has reports whether a is one of the gateway's own addresses.
func (l *localAddrs) Has(a tcpip.Address) bool {
	return l.has(a)
}

// NewHostFilter wraps a link endpoint so the stack only proxy-answers
// ARP/NDP for its own addresses (see hostfilter.go).
func NewHostFilter(lower stack.LinkEndpoint, l *LocalAddrs) stack.LinkEndpoint {
	return newHostFilter(lower, l)
}

// CreateNIC creates a NIC with spoofing and promiscuous mode enabled, as the
// transparent-forwarding stack requires.
func CreateNIC(s *stack.Stack, nic tcpip.NICID, ep stack.LinkEndpoint) error {
	return createNIC(s, nic, ep)
}

func NetParseIP(s string) net.IP {
	return netParseIP(s)
}

func SetLogConnections(v bool) {
	logConnections = v
}

// sharedLocalRoutes polls the host routing table once for all gateways.
var (
	sharedLocalRoutes     LocalRoutes
	sharedLocalRoutesOnce sync.Once
)

// GatewayStateOpts configures a gateway State. NatRanges feed the static
// routing deny list (guests must not reach the NAT range via routing).
type GatewayStateOpts struct {
	NatRange4             string
	NatRange6             string
	EnableHostRouting     bool
	EnableInternetRouting bool
	AllowRange            IPPortRangeSlice
	DenyRange             IPPortRangeSlice
	SourceIPv4            net.IP
	SourceIPv6            net.IP
}

// NewGatewayState builds a State equivalent to what Main() assembles from
// flags, minus the (static) remote-forward maps, which DynFwdTable replaces.
func NewGatewayState(o GatewayStateOpts) *State {
	sharedLocalRoutesOnce.Do(func() {
		sharedLocalRoutes.Start(30 * time.Second)
	})

	state := &State{}
	state.localRoutes = &sharedLocalRoutes
	state.enableHostRouting = o.EnableHostRouting
	state.enableInternetRouting = o.EnableInternetRouting
	state.allowRange = o.AllowRange
	state.denyRange = o.DenyRange
	state.srcIPs.srcIPv4 = o.SourceIPv4
	state.srcIPs.srcIPv6 = o.SourceIPv6

	state.StaticRoutingDeny = append(state.StaticRoutingDeny,
		MustParseCIDR("0.0.0.0/8"),
		MustParseCIDR("127.0.0.0/8"),
		MustParseCIDR("255.255.255.255/32"),
		MustParseCIDR("::/128"),
		MustParseCIDR("::1/128"),
		MustParseCIDR("::/96"),
		MustParseCIDR("::ffff:0:0:0/96"),
		MustParseCIDR("64:ff9b::/96"),
	)
	if o.NatRange4 != "" {
		state.StaticRoutingDeny = append(state.StaticRoutingDeny, MustParseCIDR(o.NatRange4))
	}
	if o.NatRange6 != "" {
		state.StaticRoutingDeny = append(state.StaticRoutingDeny, MustParseCIDR(o.NatRange6))
	}
	return state
}

// DynFwdTable holds remote-forward rules (guest connects to gateway ip:port,
// gateway dials a host address), safe for concurrent add/remove/lookup.
type DynFwdTable struct {
	mu  sync.RWMutex
	tcp map[string]*FwdAddr
	udp map[string]*FwdAddr
}

func NewDynFwdTable() *DynFwdTable {
	return &DynFwdTable{
		tcp: make(map[string]*FwdAddr),
		udp: make(map[string]*FwdAddr),
	}
}

func (t *DynFwdTable) byNetwork(network string) (map[string]*FwdAddr, error) {
	switch network {
	case "tcp":
		return t.tcp, nil
	case "udp":
		return t.udp, nil
	}
	return nil, fmt.Errorf("unknown network type %q", network)
}

// Add registers a rule under its bind address. The key returned is the one
// Remove expects.
func (t *DynFwdTable) Add(f *FwdAddr) (string, error) {
	bindAddr, err := f.BindAddr()
	if err != nil {
		return "", err
	}
	key := bindAddr.String()

	t.mu.Lock()
	defer t.mu.Unlock()
	m, err := t.byNetwork(f.network)
	if err != nil {
		return "", err
	}
	if _, busy := m[key]; busy {
		return "", fmt.Errorf("forward %s://%s already exists", f.network, key)
	}
	m[key] = f
	return key, nil
}

func (t *DynFwdTable) Remove(network, key string) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	m, err := t.byNetwork(network)
	if err != nil {
		return false
	}
	if _, ok := m[key]; !ok {
		return false
	}
	delete(m, key)
	return true
}

func (t *DynFwdTable) lookup(network, key string) *FwdAddr {
	t.mu.RLock()
	defer t.mu.RUnlock()
	m, err := t.byNetwork(network)
	if err != nil {
		return nil
	}
	return m[key]
}

// List returns network->bindKey->rule snapshots for the API.
func (t *DynFwdTable) List() map[string]map[string]*FwdAddr {
	t.mu.RLock()
	defer t.mu.RUnlock()
	out := map[string]map[string]*FwdAddr{"tcp": {}, "udp": {}}
	for k, v := range t.tcp {
		out["tcp"][k] = v
	}
	for k, v := range t.udp {
		out["udp"][k] = v
	}
	return out
}

// DynUdpRoutingHandler is UdpRoutingHandler (routing.go) with the static
// remote-forward map swapped for a DynFwdTable.
func DynUdpRoutingHandler(s *stack.Stack, state *State, t *DynFwdTable) func(*udp.ForwarderRequest) bool {
	return func(r *udp.ForwarderRequest) bool {
		var wq waiter.Queue
		ep, err := r.CreateEndpoint(&wq)
		if err != nil {
			fmt.Printf("r.CreateEndpoint() = %v\n", err)
			return true
		}

		id := r.ID()
		loc := &net.UDPAddr{
			IP:   netParseIP(id.LocalAddress.String()),
			Port: int(id.LocalPort),
		}

		rf := t.lookup("udp", loc.String())
		if rf == nil {
			if block := FirewallRoutingBlock(state, loc); block {
				ep.Close()
				return true
			}
		}

		xconn := gonet.NewUDPConn(&wq, ep)
		conn := &KaUDPConn{Conn: xconn}

		if rf != nil && rf.kaEnable && rf.kaInterval == 0 {
			conn.closeOnWrite = true
		}

		go func() {
			if rf != nil {
				RemoteForward(conn, &state.srcIPs, rf)
			} else {
				RoutingForward(conn, &state.srcIPs, loc)
			}
		}()
		return true
	}
}

// DynTcpRoutingHandler is TcpRoutingHandler (routing.go) with the static
// remote-forward map swapped for a DynFwdTable.
func DynTcpRoutingHandler(state *State, t *DynFwdTable) func(*tcp.ForwarderRequest) {
	return func(r *tcp.ForwarderRequest) {
		id := r.ID()
		loc := &net.TCPAddr{
			IP:   netParseIP(id.LocalAddress.String()),
			Port: int(id.LocalPort),
		}

		rf := t.lookup("tcp", loc.String())
		if rf == nil {
			if block := FirewallRoutingBlock(state, loc); block {
				r.Complete(true)
				return
			}
		}

		var wq waiter.Queue
		ep, errx := r.CreateEndpoint(&wq)
		if errx != nil {
			fmt.Printf("r.CreateEndpoint() = %v\n", errx)
			return
		}
		r.Complete(false)
		ep.SocketOptions().SetDelayOption(true)

		xconn := gonet.NewTCPConn(&wq, ep)
		conn := &GonetTCPConn{xconn, ep}

		go func() {
			if rf != nil {
				RemoteForward(conn, &state.srcIPs, rf)
			} else {
				RoutingForward(conn, &state.srcIPs, loc)
			}
		}()
	}
}

// NewFwdAddr builds a forward rule from already-split host/port strings
// (hosts may be DNS labels; see ParseDefAddress). network is "tcp" or "udp".
func NewFwdAddr(network, bindHost, bindPort, hostHost, hostPort string) (*FwdAddr, error) {
	switch network {
	case "tcp", "udp":
	default:
		return nil, fmt.Errorf("unknown network type %q", network)
	}
	bind, err := ParseDefAddress(bindHost, bindPort)
	if err != nil {
		return nil, fmt.Errorf("bad bind address: %w", err)
	}
	host, err := ParseDefAddress(hostHost, hostPort)
	if err != nil {
		return nil, fmt.Errorf("bad host address: %w", err)
	}
	return &FwdAddr{network: network, bind: *bind, host: *host}, nil
}

// DynLocalForwardTCP/UDP wrap the upstream by-value LocalForward entry
// points behind pointer signatures (FwdAddr embeds a mutex, so the copy must
// happen inside this package to keep callers vet-clean).

func DynLocalForwardTCP(state *State, s *stack.Stack, rf *FwdAddr) (Listener, error) {
	return LocalForwardTCP(state, s, *rf, nil)
}

func DynLocalForwardUDP(state *State, s *stack.Stack, rf *FwdAddr) (Listener, error) {
	return LocalForwardUDP(state, s, *rf, nil)
}

// Accessors for the REST API (FwdAddr fields are package-internal).

func (f *FwdAddr) Network() string {
	return f.network
}

func (f *FwdAddr) BindString() string {
	return f.bind.String()
}

func (f *FwdAddr) HostString() string {
	return f.host.String()
}
