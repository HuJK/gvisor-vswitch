package switchcore

import (
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

const (
	defaultFDBMaxAge  = 5 * time.Minute
	fdbExpireInterval = 30 * time.Second
)

type portEntry struct {
	id    string
	port  Port
	attrs PortAttrs
	stats portCounters
	// gone flips when the entry is unregistered, invalidating cached
	// PortRef pointers.
	gone atomic.Bool
}

// PortRef is a port's fast handle into the switch: Deliver resolves the
// port-registry entry once and then reuses the pointer, so the per-frame
// path does no string-keyed map lookups.
type PortRef struct {
	sw     *Switch
	id     string
	cached atomic.Pointer[portEntry]
}

// Ref returns a delivery handle for the named port. It may be created
// before the port is registered; resolution is lazy.
func (s *Switch) Ref(id string) *PortRef {
	return &PortRef{sw: s, id: id}
}

// Deliver switches one ingress frame from this port.
func (r *PortRef) Deliver(frame []byte) {
	e := r.cached.Load()
	if e == nil || e.gone.Load() {
		r.sw.mu.RLock()
		e = r.sw.ports[r.id]
		r.sw.mu.RUnlock()
		if e == nil {
			return // not (yet) registered
		}
		r.cached.Store(e)
	}
	r.sw.deliver(e, frame)
}

type portCounters struct {
	rxFrames, rxBytes, rxDropped atomic.Uint64
	txFrames, txBytes, txDropped atomic.Uint64
}

func (c *portCounters) snapshot() PortStats {
	return PortStats{
		RxFrames:  c.rxFrames.Load(),
		RxBytes:   c.rxBytes.Load(),
		RxDropped: c.rxDropped.Load(),
		TxFrames:  c.txFrames.Load(),
		TxBytes:   c.txBytes.Load(),
		TxDropped: c.txDropped.Load(),
	}
}

// Switch is a VLAN-aware learning switch. All methods are safe for
// concurrent use.
type Switch struct {
	mu    sync.RWMutex
	ports map[string]*portEntry

	fdb *fdb

	downMu sync.RWMutex
	downCB []func(portID string)

	stop     chan struct{}
	stopOnce sync.Once
}

func New() *Switch {
	s := &Switch{
		ports: make(map[string]*portEntry),
		fdb:   newFDB(defaultFDBMaxAge),
		stop:  make(chan struct{}),
	}
	go s.ageLoop()
	return s
}

func (s *Switch) ageLoop() {
	t := time.NewTicker(fdbExpireInterval)
	defer t.Stop()
	for {
		select {
		case <-t.C:
			s.fdb.expire()
		case <-s.stop:
			return
		}
	}
}

// Close stops background work and closes all ports.
func (s *Switch) Close() {
	s.stopOnce.Do(func() { close(s.stop) })
	s.mu.Lock()
	ports := s.ports
	s.ports = make(map[string]*portEntry)
	s.mu.Unlock()
	for _, e := range ports {
		e.port.Close()
	}
}

// AddPort registers a port. The ID must be unique.
func (s *Switch) AddPort(p Port, attrs PortAttrs) error {
	if err := attrs.validate(); err != nil {
		return err
	}
	id := p.ID()
	if id == "" {
		return fmt.Errorf("port identifier must not be empty")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, dup := s.ports[id]; dup {
		return fmt.Errorf("port %q already exists", id)
	}
	s.ports[id] = &portEntry{id: id, port: p, attrs: attrs}
	return nil
}

// RemovePort unregisters and closes a port, flushes its FDB entries and
// fires port-down notifications. It is a no-op for unknown IDs.
func (s *Switch) RemovePort(id string) {
	s.mu.Lock()
	e, ok := s.ports[id]
	if ok {
		delete(s.ports, id)
	}
	s.mu.Unlock()
	if !ok {
		return
	}
	e.gone.Store(true)
	e.port.Close()
	s.portDown(id)
}

// NotifyDown is called by port implementations when their transport went
// offline while the port itself stays registered (e.g. a server port whose
// client disconnected). It flushes learned MACs and fires port-down hooks.
func (s *Switch) NotifyDown(id string) {
	s.portDown(id)
}

func (s *Switch) portDown(id string) {
	s.fdb.flushPort(id)
	s.downMu.RLock()
	cbs := s.downCB
	s.downMu.RUnlock()
	for _, cb := range cbs {
		cb(id)
	}
}

// OnPortDown registers a hook fired whenever a port goes offline or is
// removed (the gateway uses this to release DHCP leases).
func (s *Switch) OnPortDown(cb func(portID string)) {
	s.downMu.Lock()
	s.downCB = append(s.downCB, cb)
	s.downMu.Unlock()
}

// PortAttrs returns the attributes of a port.
func (s *Switch) PortAttrs(id string) (PortAttrs, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	e, ok := s.ports[id]
	if !ok {
		return PortAttrs{}, false
	}
	return e.attrs, true
}

// UpdatePortAttrs replaces a port's attributes. Changing the VLAN flushes
// the port's FDB entries.
func (s *Switch) UpdatePortAttrs(id string, attrs PortAttrs) error {
	if err := attrs.validate(); err != nil {
		return err
	}
	s.mu.Lock()
	e, ok := s.ports[id]
	if !ok {
		s.mu.Unlock()
		return fmt.Errorf("port %q not found", id)
	}
	vlanChanged := e.attrs.VLAN != attrs.VLAN
	e.attrs = attrs
	s.mu.Unlock()
	if vlanChanged {
		s.fdb.flushPort(id)
	}
	return nil
}

// PortStats returns the traffic counters of a port.
func (s *Switch) PortStats(id string) (PortStats, bool) {
	s.mu.RLock()
	e, ok := s.ports[id]
	s.mu.RUnlock()
	if !ok {
		return PortStats{}, false
	}
	return e.stats.snapshot(), true
}

// FDB returns a snapshot of the forwarding database.
func (s *Switch) FDB() []FDBEntry {
	return s.fdb.snapshot()
}

// AddStaticFDB installs an admin-managed forwarding entry. The entry never
// ages, survives port removal, and learning cannot override it. vlan is 0
// for the untagged domain or 1-4094.
func (s *Switch) AddStaticFDB(vlan int, mac net.HardwareAddr, portID string) error {
	if vlan < 0 || vlan > 4094 {
		return fmt.Errorf("static fdb vlan must be 0 (untagged domain) or 1-4094, got %d", vlan)
	}
	if portID == "" {
		return fmt.Errorf("static fdb entry needs a port")
	}
	m, err := macKey(mac)
	if err != nil {
		return err
	}
	if isMulticast(m) {
		return fmt.Errorf("static fdb MAC must be unicast")
	}
	s.fdb.addStatic(int32(vlan), m, portID)
	return nil
}

// RemoveStaticFDB deletes a static forwarding entry.
func (s *Switch) RemoveStaticFDB(vlan int, mac net.HardwareAddr) error {
	m, err := macKey(mac)
	if err != nil {
		return err
	}
	return s.fdb.removeStatic(int32(vlan), m)
}

// DeleteFDBEntry removes one learned (dynamic) entry.
func (s *Switch) DeleteFDBEntry(vlan int, mac net.HardwareAddr) error {
	m, err := macKey(mac)
	if err != nil {
		return err
	}
	return s.fdb.removeDynamic(int32(vlan), m)
}

// FlushFDB removes dynamic entries matching the filters (portID "" and
// vlan nil match all) and returns the number removed.
func (s *Switch) FlushFDB(portID string, vlan *int) int {
	var v *int32
	if vlan != nil {
		x := int32(*vlan)
		v = &x
	}
	return s.fdb.flush(portID, v)
}

// FDBMaxAge returns the dynamic-entry aging time.
func (s *Switch) FDBMaxAge() time.Duration {
	return s.fdb.getMaxAge()
}

// SetFDBMaxAge changes the dynamic-entry aging time.
func (s *Switch) SetFDBMaxAge(d time.Duration) error {
	if d <= 0 {
		return fmt.Errorf("aging time must be positive")
	}
	s.fdb.setMaxAge(d)
	return nil
}

// PortIDs returns the registered port identifiers.
func (s *Switch) PortIDs() []string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]string, 0, len(s.ports))
	for id := range s.ports {
		out = append(out, id)
	}
	return out
}

// Deliver switches one ingress frame from the named port. The frame buffer
// is owned by the switch after the call. Ports on the hot path use
// PortRef.Deliver instead, which skips the per-frame registry lookup.
func (s *Switch) Deliver(srcID string, frame []byte) {
	s.mu.RLock()
	src, ok := s.ports[srcID]
	s.mu.RUnlock()
	if !ok {
		return
	}
	s.deliver(src, frame)
}

// deliver is the forwarding pipeline. Lookups on the hot path are
// pointer-based: the source entry comes in directly, and dynamic FDB hits
// carry the destination entry pointer; only static FDB entries (which may
// name not-yet-registered ports) resolve by ID.
func (s *Switch) deliver(src *portEntry, frame []byte) {
	f, ok := parseFrame(frame)
	if !ok {
		return
	}
	srcID := src.id

	s.mu.RLock()
	if src.gone.Load() {
		s.mu.RUnlock()
		return
	}
	srcAttrs := src.attrs
	src.stats.rxFrames.Add(1)
	src.stats.rxBytes.Add(uint64(len(frame)))

	if srcAttrs.Disabled {
		src.stats.rxDropped.Add(1)
		s.mu.RUnlock()
		return
	}

	key, ok := ingressKey(srcAttrs, f)
	if !ok {
		src.stats.rxDropped.Add(1)
		s.mu.RUnlock()
		return
	}

	srcMAC := f.srcMAC()
	if srcAttrs.SecurityMAC != nil {
		var want [macLen]byte
		copy(want[:], srcAttrs.SecurityMAC)
		if srcMAC != want {
			src.stats.rxDropped.Add(1)
			s.mu.RUnlock()
			return
		}
	}

	if !isMulticast(srcMAC) {
		s.fdb.learn(key, srcMAC, src)
	}

	v := frameVariants{f: f, key: key}
	meta := Meta{SrcPortID: srcID}

	send := func(dst *portEntry) {
		out := v.egressFrame(dst.attrs)
		if dst.port.Send(meta, out) {
			dst.stats.txFrames.Add(1)
			dst.stats.txBytes.Add(uint64(len(out)))
		} else {
			dst.stats.txDropped.Add(1)
		}
	}

	dstMAC := f.dstMAC()
	if !isMulticast(dstMAC) {
		if dst, dstID := s.fdb.lookup(key, dstMAC); dstID != "" {
			if dst == nil {
				// Static entry: resolve by ID (the port may not exist).
				dst = s.ports[dstID]
			}
			if dst != nil && dst.id != srcID && !dst.gone.Load() && egressEligible(srcAttrs, dst.attrs, key) {
				send(dst)
			}
			s.mu.RUnlock()
			return
		}
	}

	// Broadcast, multicast, or unknown unicast: flood.
	for id, dst := range s.ports {
		if id == srcID || !egressEligible(srcAttrs, dst.attrs, key) {
			continue
		}
		send(dst)
	}
	s.mu.RUnlock()
}
