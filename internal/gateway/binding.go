package gateway

import (
	"fmt"
	"net/netip"
	"sort"
	"strings"
	"sync"
	"time"
)

// StaticBinding pins an IP to a client matched by AND-ed conditions; nil
// fields are wildcards. Used by both DHCPv4 (ClientID = option 61, hex) and
// DHCPv6 (ClientID = DUID, hex).
type StaticBinding struct {
	ID       string
	Order    int
	PortID   *string
	MAC      *string // canonical form, e.g. "02:00:00:00:00:01"
	ClientID *string // lowercase hex
	IP       netip.Addr
}

func (b *StaticBinding) validate() error {
	if b.PortID == nil && b.MAC == nil && b.ClientID == nil {
		return fmt.Errorf("static binding needs at least one condition")
	}
	if !b.IP.IsValid() {
		return fmt.Errorf("static binding needs a valid ip")
	}
	return nil
}

// matchBinding picks the binding for a client: every non-wildcard condition
// must match; the binding matching the most conditions wins; ties go to the
// higher Order.
func matchBinding(bindings []*StaticBinding, portID, mac, clientID string) *StaticBinding {
	var best *StaticBinding
	bestScore := 0
	for _, b := range bindings {
		score := 0
		if b.PortID != nil {
			if *b.PortID != portID {
				continue
			}
			score++
		}
		if b.MAC != nil {
			if !strings.EqualFold(*b.MAC, mac) {
				continue
			}
			score++
		}
		if b.ClientID != nil {
			if !strings.EqualFold(*b.ClientID, clientID) {
				continue
			}
			score++
		}
		if score == 0 {
			continue
		}
		if best == nil || score > bestScore || (score == bestScore && b.Order > best.Order) {
			best = b
			bestScore = score
		}
	}
	return best
}

// Lease is one address assignment.
type Lease struct {
	IP       netip.Addr
	MAC      string
	ClientID string
	PortID   string
	Expiry   time.Time
	Static   bool
}

// leaseTable tracks active leases for one address family.
type leaseTable struct {
	mu     sync.Mutex
	leases map[netip.Addr]*Lease
	now    func() time.Time
}

func newLeaseTable() *leaseTable {
	return &leaseTable{leases: make(map[netip.Addr]*Lease), now: time.Now}
}

// clientKey identifies a client for lease reuse.
func clientKey(mac, clientID string) string {
	return strings.ToLower(mac) + "/" + strings.ToLower(clientID)
}

func (t *leaseTable) get(ip netip.Addr) *Lease {
	t.mu.Lock()
	defer t.mu.Unlock()
	l := t.leases[ip]
	if l == nil || t.now().After(l.Expiry) {
		return nil
	}
	cp := *l
	return &cp
}

// byClient finds the client's active lease.
func (t *leaseTable) byClient(mac, clientID string) *Lease {
	key := clientKey(mac, clientID)
	t.mu.Lock()
	defer t.mu.Unlock()
	for _, l := range t.leases {
		if clientKey(l.MAC, l.ClientID) == key && !t.now().After(l.Expiry) {
			cp := *l
			return &cp
		}
	}
	return nil
}

func (t *leaseTable) set(l Lease) {
	t.mu.Lock()
	t.leases[l.IP] = &l
	t.mu.Unlock()
}

func (t *leaseTable) release(ip netip.Addr) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	if _, ok := t.leases[ip]; !ok {
		return false
	}
	delete(t.leases, ip)
	return true
}

// releaseByPort drops all leases tied to a switchport (port went offline).
func (t *leaseTable) releaseByPort(portID string) {
	t.mu.Lock()
	for ip, l := range t.leases {
		if l.PortID == portID {
			delete(t.leases, ip)
		}
	}
	t.mu.Unlock()
}

// inUse reports whether ip currently has an unexpired lease held by a
// different client.
func (t *leaseTable) inUse(ip netip.Addr, mac, clientID string) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	l := t.leases[ip]
	if l == nil || t.now().After(l.Expiry) {
		return false
	}
	return clientKey(l.MAC, l.ClientID) != clientKey(mac, clientID)
}

func (t *leaseTable) expireSweep() {
	now := t.now()
	t.mu.Lock()
	for ip, l := range t.leases {
		if now.After(l.Expiry) {
			delete(t.leases, ip)
		}
	}
	t.mu.Unlock()
}

func (t *leaseTable) snapshot() []Lease {
	t.mu.Lock()
	defer t.mu.Unlock()
	out := make([]Lease, 0, len(t.leases))
	now := t.now()
	for _, l := range t.leases {
		if now.After(l.Expiry) {
			continue
		}
		out = append(out, *l)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].IP.Less(out[j].IP) })
	return out
}

// allocate finds a free address in [start, end], skipping skip() addresses
// and active leases, and records the lease. Returns the invalid Addr when
// the pool is exhausted.
func (t *leaseTable) allocate(start, end netip.Addr, skip func(netip.Addr) bool, l Lease) netip.Addr {
	t.mu.Lock()
	defer t.mu.Unlock()
	now := t.now()
	for ip := start; ip.IsValid() && !end.Less(ip); ip = ip.Next() {
		if skip(ip) {
			continue
		}
		if cur, ok := t.leases[ip]; ok && !now.After(cur.Expiry) {
			continue
		}
		l.IP = ip
		t.leases[ip] = &l
		return ip
	}
	return netip.Addr{}
}
