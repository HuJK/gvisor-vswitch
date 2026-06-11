package switchcore

import (
	"fmt"
	"net"
	"sync"
	"time"
)

type fdbKey struct {
	vlan int32
	mac  [macLen]byte
}

type fdbEntry struct {
	portID string
	// port is the live registry entry for dynamic entries (learning has
	// it at hand), letting Deliver skip the by-ID lookup. Static entries
	// keep it nil: they may name ports that don't exist yet.
	port     *portEntry
	lastSeen time.Time
	static   bool
}

// fdb is the forwarding database: (vlan, mac) -> port, with aging. Static
// entries are admin-managed: learning never overrides them, they do not
// age, and flushes leave them alone.
type fdb struct {
	mu     sync.RWMutex
	m      map[fdbKey]fdbEntry
	maxAge time.Duration
	now    func() time.Time // injectable for tests
}

func newFDB(maxAge time.Duration) *fdb {
	return &fdb{
		m:      make(map[fdbKey]fdbEntry),
		maxAge: maxAge,
		now:    time.Now,
	}
}

func (f *fdb) learn(vlan int32, mac [macLen]byte, src *portEntry) {
	k := fdbKey{vlan, mac}
	f.mu.Lock()
	if e, ok := f.m[k]; !ok || !e.static {
		f.m[k] = fdbEntry{portID: src.id, port: src, lastSeen: f.now()}
	}
	f.mu.Unlock()
}

// lookup returns the port the MAC was last seen on: a direct entry pointer
// for dynamic entries (nil for static ones), plus the port ID. The ID is
// "" on miss/expiry.
func (f *fdb) lookup(vlan int32, mac [macLen]byte) (*portEntry, string) {
	f.mu.RLock()
	e, ok := f.m[fdbKey{vlan, mac}]
	maxAge := f.maxAge
	f.mu.RUnlock()
	if !ok {
		return nil, ""
	}
	if !e.static && f.now().Sub(e.lastSeen) > maxAge {
		return nil, ""
	}
	return e.port, e.portID
}

func (f *fdb) setMaxAge(d time.Duration) {
	f.mu.Lock()
	f.maxAge = d
	f.mu.Unlock()
}

func (f *fdb) getMaxAge() time.Duration {
	f.mu.RLock()
	defer f.mu.RUnlock()
	return f.maxAge
}

// addStatic installs or replaces an admin-managed entry.
func (f *fdb) addStatic(vlan int32, mac [macLen]byte, portID string) {
	f.mu.Lock()
	f.m[fdbKey{vlan, mac}] = fdbEntry{portID: portID, lastSeen: f.now(), static: true}
	f.mu.Unlock()
}

// removeStatic deletes a static entry.
func (f *fdb) removeStatic(vlan int32, mac [macLen]byte) error {
	k := fdbKey{vlan, mac}
	f.mu.Lock()
	defer f.mu.Unlock()
	e, ok := f.m[k]
	if !ok || !e.static {
		return fmt.Errorf("static fdb entry not found")
	}
	delete(f.m, k)
	return nil
}

// removeDynamic deletes one learned entry.
func (f *fdb) removeDynamic(vlan int32, mac [macLen]byte) error {
	k := fdbKey{vlan, mac}
	f.mu.Lock()
	defer f.mu.Unlock()
	e, ok := f.m[k]
	if !ok {
		return fmt.Errorf("fdb entry not found")
	}
	if e.static {
		return fmt.Errorf("entry is static; delete it via the static fdb API")
	}
	delete(f.m, k)
	return nil
}

// flushPort drops the dynamic entries learned on a port.
func (f *fdb) flushPort(portID string) {
	f.mu.Lock()
	for k, e := range f.m {
		if !e.static && e.portID == portID {
			delete(f.m, k)
		}
	}
	f.mu.Unlock()
}

// flush drops dynamic entries matching the optional filters and reports how
// many were removed. portID "" and vlan nil match everything.
func (f *fdb) flush(portID string, vlan *int32) int {
	n := 0
	f.mu.Lock()
	for k, e := range f.m {
		if e.static {
			continue
		}
		if portID != "" && e.portID != portID {
			continue
		}
		if vlan != nil && k.vlan != *vlan {
			continue
		}
		delete(f.m, k)
		n++
	}
	f.mu.Unlock()
	return n
}

func (f *fdb) expire() {
	f.mu.Lock()
	cutoff := f.now().Add(-f.maxAge)
	for k, e := range f.m {
		if !e.static && e.lastSeen.Before(cutoff) {
			delete(f.m, k)
		}
	}
	f.mu.Unlock()
}

// FDBEntry is a snapshot row for the API.
type FDBEntry struct {
	VLAN   int32 // 0 = untagged domain
	MAC    string
	PortID string
	Age    time.Duration
	Static bool
}

func (f *fdb) snapshot() []FDBEntry {
	now := f.now()
	f.mu.RLock()
	defer f.mu.RUnlock()
	out := make([]FDBEntry, 0, len(f.m))
	for k, e := range f.m {
		age := now.Sub(e.lastSeen)
		if !e.static && age > f.maxAge {
			continue
		}
		row := FDBEntry{
			VLAN:   k.vlan,
			MAC:    macString(k.mac),
			PortID: e.portID,
			Static: e.static,
		}
		if !e.static {
			row.Age = age
		}
		out = append(out, row)
	}
	return out
}

func macString(m [macLen]byte) string {
	const hex = "0123456789abcdef"
	out := make([]byte, 0, 17)
	for i, b := range m {
		if i > 0 {
			out = append(out, ':')
		}
		out = append(out, hex[b>>4], hex[b&0xf])
	}
	return string(out)
}

func macKey(mac net.HardwareAddr) ([macLen]byte, error) {
	var m [macLen]byte
	if len(mac) != macLen {
		return m, fmt.Errorf("MAC must be 6 bytes")
	}
	copy(m[:], mac)
	return m, nil
}
