package switchcore

import (
	"encoding/binary"
	"sync"
	"time"
)

// Classic 802.1D (1998) spanning tree, single tree for the whole bridge.
// Per-port participation is opt-in (PortAttrs.STP); non-participating
// ports stay in the zero (forwarding) state and have their BPDUs consumed
// elsewhere. The implementation is the textbook timer-based variant:
// configuration BPDUs flow from the root, ports hold the best received
// priority vector, roles are recomputed on every change, and state
// transitions walk Blocking -> Listening -> Learning -> Forwarding paced
// by ForwardDelay.

// STPConfig is the bridge-wide configuration.
type STPConfig struct {
	Enabled      bool
	Priority     uint16 // bridge priority, default 32768
	HelloTime    time.Duration
	MaxAge       time.Duration
	ForwardDelay time.Duration
}

func defaultSTPConfig() STPConfig {
	return STPConfig{
		Priority:     32768,
		HelloTime:    2 * time.Second,
		MaxAge:       20 * time.Second,
		ForwardDelay: 15 * time.Second,
	}
}

// STPPortStatus is the externally visible per-port state.
type STPPortStatus struct {
	State string `json:"state"` // forwarding|blocking|listening|learning|-
	Role  string `json:"role"`  // root|designated|blocked|-
}

// STPStatus is the externally visible bridge state.
type STPStatus struct {
	Enabled             bool   `json:"enabled"`
	BridgeID            string `json:"bridge_id"`
	RootID              string `json:"root_id"`
	IsRoot              bool   `json:"is_root"`
	RootPort            string `json:"root_port,omitempty"`
	RootPathCost        uint32 `json:"root_path_cost"`
	Priority            uint16 `json:"priority"`
	HelloSeconds        int    `json:"hello_seconds"`
	MaxAgeSeconds       int    `json:"max_age_seconds"`
	ForwardDelaySeconds int    `json:"forward_delay_seconds"`
	TopologyChange      bool   `json:"topology_change"`
}

// priorityVector orders STP information; lower is better.
type priorityVector struct {
	rootID   uint64
	cost     uint32
	bridgeID uint64
	portID   uint16
}

func (a priorityVector) better(b priorityVector) bool {
	if a.rootID != b.rootID {
		return a.rootID < b.rootID
	}
	if a.cost != b.cost {
		return a.cost < b.cost
	}
	if a.bridgeID != b.bridgeID {
		return a.bridgeID < b.bridgeID
	}
	return a.portID < b.portID
}

// stpPort is the per-port protocol state (only for participating ports).
type stpPort struct {
	entry *portEntry

	role string // root|designated|blocked

	// Best received info on this segment (valid while age < MaxAge).
	hasInfo bool
	info    priorityVector
	infoAge time.Duration
	rxTimes [3]time.Duration // maxAge, hello, fwdDelay from root, in seconds

	// forward-delay progression timer for listening/learning.
	stateTimer time.Duration
}

type stpBridge struct {
	sw *Switch

	mu  sync.Mutex
	cfg STPConfig
	mac [6]byte // bridge MAC (random, stable per instance)

	ports map[string]*stpPort

	rootID   uint64
	rootCost uint32
	rootPort string // "" when we are root

	// topology change machinery
	tcWhile    time.Duration // root: how long to set TC in configs
	tcnPending bool          // non-root: keep sending TCN until acked

	lastHello time.Duration
	now       time.Duration // monotonic, advanced by run()
}

func newSTPBridge(s *Switch) *stpBridge {
	b := &stpBridge{
		sw:    s,
		cfg:   defaultSTPConfig(),
		ports: make(map[string]*stpPort),
	}
	// Bridge MAC derived from the switch instance ID (locally
	// administered unicast).
	b.mac[0] = 0x02
	binary.BigEndian.PutUint32(b.mac[1:5], uint32(s.instanceID>>24))
	b.mac[5] = byte(s.instanceID)
	return b
}

func (b *stpBridge) bridgeID() uint64 {
	return uint64(b.cfg.Priority)<<48 |
		uint64(b.mac[0])<<40 | uint64(b.mac[1])<<32 | uint64(b.mac[2])<<24 |
		uint64(b.mac[3])<<16 | uint64(b.mac[4])<<8 | uint64(b.mac[5])
}

func portID(prio uint8, num uint16) uint16 {
	return uint16(prio)<<8 | num&0xff
}

// SetConfig applies bridge-level STP configuration.
func (s *Switch) SetSTPConfig(cfg STPConfig) error {
	b := s.stp
	if cfg.Priority == 0 {
		cfg.Priority = 32768
	}
	if cfg.HelloTime <= 0 {
		cfg.HelloTime = 2 * time.Second
	}
	if cfg.MaxAge <= 0 {
		cfg.MaxAge = 20 * time.Second
	}
	if cfg.ForwardDelay <= 0 {
		cfg.ForwardDelay = 15 * time.Second
	}

	b.mu.Lock()
	s.mu.Lock()
	b.cfg = cfg
	if !cfg.Enabled {
		// Tear down: every port back to plain forwarding.
		for _, sp := range b.ports {
			sp.entry.stpState.Store(stpForwarding)
		}
		b.ports = make(map[string]*stpPort)
	} else {
		b.resyncPortsLocked()
		b.becomeRootLocked()
	}
	s.mu.Unlock()
	b.mu.Unlock()
	return nil
}

// STPStatus snapshots bridge and per-port state.
func (s *Switch) STPStatus() (STPStatus, map[string]STPPortStatus) {
	b := s.stp
	b.mu.Lock()
	defer b.mu.Unlock()
	st := STPStatus{
		Enabled:             b.cfg.Enabled,
		BridgeID:            formatBridgeID(b.bridgeID()),
		RootID:              formatBridgeID(b.rootID),
		IsRoot:              b.rootPort == "",
		RootPort:            b.rootPort,
		RootPathCost:        b.rootCost,
		Priority:            b.cfg.Priority,
		HelloSeconds:        int(b.cfg.HelloTime / time.Second),
		MaxAgeSeconds:       int(b.cfg.MaxAge / time.Second),
		ForwardDelaySeconds: int(b.cfg.ForwardDelay / time.Second),
		TopologyChange:      b.tcWhile > 0 || b.tcnPending,
	}
	if !b.cfg.Enabled {
		st.RootID = ""
		st.IsRoot = false
	}
	ports := make(map[string]STPPortStatus, len(b.ports))
	for id, sp := range b.ports {
		ports[id] = STPPortStatus{
			State: stpStateName(sp.entry.stpState.Load()),
			Role:  sp.role,
		}
	}
	return st, ports
}

// STPPortStatus returns one port's spanning-tree state.
func (s *Switch) STPPortStatus(id string) (STPPortStatus, bool) {
	b := s.stp
	b.mu.Lock()
	defer b.mu.Unlock()
	sp, ok := b.ports[id]
	if !ok {
		return STPPortStatus{State: "-", Role: "-"}, false
	}
	return STPPortStatus{
		State: stpStateName(sp.entry.stpState.Load()),
		Role:  sp.role,
	}, true
}

func stpStateName(v uint32) string {
	switch v {
	case stpBlocking:
		return "blocking"
	case stpListening:
		return "listening"
	case stpLearning:
		return "learning"
	default:
		return "forwarding"
	}
}

func formatBridgeID(id uint64) string {
	const hex = "0123456789abcdef"
	out := make([]byte, 0, 23)
	for i := 7; i >= 0; i-- {
		v := byte(id >> (8 * i))
		out = append(out, hex[v>>4], hex[v&0xf])
		if i == 6 || (i > 0 && i < 6) {
			out = append(out, '.')
		}
	}
	return string(out)
}

// portChangedLocked is called (with Switch.mu held) when a port is added or
// its attributes change, to enrol/withdraw it from the tree.
func (b *stpBridge) portChangedLocked(e *portEntry) {
	b.sw.runAsync(func() {
		b.mu.Lock()
		b.sw.mu.Lock()
		if b.cfg.Enabled {
			b.resyncPortsLocked()
			b.recomputeLocked()
		}
		b.sw.mu.Unlock()
		b.mu.Unlock()
	})
}

// resyncPortsLocked aligns the STP port set with participating switch
// ports. Both locks held.
func (b *stpBridge) resyncPortsLocked() {
	seen := make(map[string]bool)
	for id, e := range b.sw.ports {
		if !e.attrs.STP || e.attrs.Disabled {
			continue
		}
		seen[id] = true
		if _, ok := b.ports[id]; !ok {
			b.ports[id] = &stpPort{entry: e, role: "blocked"}
			e.stpState.Store(stpBlocking)
		}
	}
	for id, sp := range b.ports {
		if !seen[id] || sp.entry.gone.Load() {
			sp.entry.stpState.Store(stpForwarding)
			delete(b.ports, id)
		}
	}
}

// becomeRootLocked resets root knowledge to ourselves.
func (b *stpBridge) becomeRootLocked() {
	b.rootID = b.bridgeID()
	b.rootCost = 0
	b.rootPort = ""
	b.recomputeLocked()
}

// recomputeLocked recalculates root selection and port roles/states from
// the stored per-port info. Both locks held.
func (b *stpBridge) recomputeLocked() {
	if !b.cfg.Enabled {
		return
	}
	myBridgeID := b.bridgeID()

	// Root selection: best of our own claim and every port's stored info
	// plus its path cost.
	best := priorityVector{rootID: myBridgeID, cost: 0, bridgeID: myBridgeID, portID: 0}
	var rootPort *stpPort
	rootPortID := ""
	for id, sp := range b.ports {
		if !sp.hasInfo || sp.info.bridgeID == myBridgeID {
			continue
		}
		cand := priorityVector{
			rootID:   sp.info.rootID,
			cost:     sp.info.cost + sp.portCost(),
			bridgeID: sp.info.bridgeID,
			portID:   sp.info.portID,
		}
		if cand.better(best) {
			best = cand
			rootPort = sp
			rootPortID = id
		}
	}
	b.rootID = best.rootID
	b.rootCost = best.cost
	b.rootPort = rootPortID

	topologyChanged := false
	for id, sp := range b.ports {
		var role string
		switch {
		case sp == rootPort:
			role = "root"
		case b.designatedLocked(sp):
			role = "designated"
		default:
			role = "blocked"
		}
		if role != sp.role {
			sp.role = role
			topologyChanged = true
		}
		b.applyRoleLocked(id, sp)
	}
	if topologyChanged {
		b.signalTopologyChangeLocked()
	}
}

// designatedLocked: we are designated on the segment if our advertisement
// beats the stored segment info.
func (b *stpBridge) designatedLocked(sp *stpPort) bool {
	mine := priorityVector{
		rootID:   b.rootID,
		cost:     b.rootCost,
		bridgeID: b.bridgeID(),
		portID:   sp.portIDValue(),
	}
	if !sp.hasInfo {
		return true
	}
	return mine.better(sp.info)
}

// applyRoleLocked moves a port's dataplane state toward its role. Root and
// designated ports climb to forwarding via listening/learning; blocked
// ports drop straight to blocking.
func (b *stpBridge) applyRoleLocked(id string, sp *stpPort) {
	cur := sp.entry.stpState.Load()
	if sp.role == "blocked" {
		if cur != stpBlocking {
			sp.entry.stpState.Store(stpBlocking)
			b.sw.fdb.flushPort(id)
		}
		return
	}
	// root/designated: start the climb if blocked.
	if cur == stpBlocking {
		sp.entry.stpState.Store(stpListening)
		sp.stateTimer = 0
	}
}

func (sp *stpPort) portCost() uint32 {
	if c := sp.entry.attrs.STPCost; c > 0 {
		return c
	}
	return 100
}

func (sp *stpPort) portIDValue() uint16 {
	prio := sp.entry.attrs.STPPriority
	if prio == 0 {
		prio = 128
	}
	return portID(prio, sp.entry.portNum)
}

func (b *stpBridge) signalTopologyChangeLocked() {
	if b.rootPort == "" {
		// We are root: advertise TC for maxAge + fwdDelay.
		b.tcWhile = b.cfg.MaxAge + b.cfg.ForwardDelay
	} else {
		b.tcnPending = true
	}
	// Fast-age our own table.
	b.sw.fdb.flush("", nil)
}

// run is the 1Hz-ish protocol clock (ticks at HelloTime/2 for snappier
// tests with small timers).
func (b *stpBridge) run() {
	for {
		b.mu.Lock()
		tick := b.cfg.HelloTime / 2
		b.mu.Unlock()
		if tick <= 0 {
			tick = time.Second
		}
		select {
		case <-b.sw.stop:
			return
		case <-time.After(tick):
		}

		b.mu.Lock()
		if !b.cfg.Enabled {
			b.mu.Unlock()
			continue
		}
		b.sw.mu.Lock()
		b.now += tick
		b.tickLocked(tick)
		b.sw.mu.Unlock()
		b.mu.Unlock()
	}
}

func (b *stpBridge) tickLocked(dt time.Duration) {
	b.resyncPortsLocked()

	// Age out stored info; expiry means the segment lost its designated
	// bridge — reclaim and recompute.
	expired := false
	for _, sp := range b.ports {
		if !sp.hasInfo {
			continue
		}
		sp.infoAge += dt
		if sp.infoAge >= b.cfg.MaxAge {
			sp.hasInfo = false
			expired = true
		}
	}
	if expired {
		b.recomputeLocked()
	}

	// Forward-delay state progression.
	for id, sp := range b.ports {
		if sp.role == "blocked" {
			continue
		}
		switch sp.entry.stpState.Load() {
		case stpListening:
			sp.stateTimer += dt
			if sp.stateTimer >= b.cfg.ForwardDelay {
				sp.entry.stpState.Store(stpLearning)
				sp.stateTimer = 0
			}
		case stpLearning:
			sp.stateTimer += dt
			if sp.stateTimer >= b.cfg.ForwardDelay {
				sp.entry.stpState.Store(stpForwarding)
				sp.stateTimer = 0
				b.sw.fdb.flushPort(id)
			}
		}
	}

	// Hello: root originates configs; everyone relays on designated
	// ports (driven here off received-info freshness).
	b.lastHello += dt
	if b.lastHello >= b.cfg.HelloTime {
		b.lastHello = 0
		b.transmitConfigsLocked()
		if b.tcWhile > 0 {
			b.tcWhile -= b.cfg.HelloTime
		}
		if b.tcnPending && b.rootPort != "" {
			if sp := b.ports[b.rootPort]; sp != nil {
				sp.entry.port.Send(Meta{SrcPortID: "stp"}, b.buildTCN())
			}
		}
	}
}

// transmitConfigsLocked sends config BPDUs out designated ports.
func (b *stpBridge) transmitConfigsLocked() {
	isRoot := b.rootPort == ""
	if !isRoot {
		// Non-root bridges relay only while they have fresh root info.
		if sp := b.ports[b.rootPort]; sp == nil || !sp.hasInfo {
			return
		}
	}
	for _, sp := range b.ports {
		if sp.role != "designated" {
			continue
		}
		flags := byte(0)
		if b.tcWhile > 0 {
			flags |= 0x01 // TC
		}
		sp.entry.port.Send(Meta{SrcPortID: "stp"}, b.buildConfig(sp, flags))
	}
}

// handleBPDU processes a BPDU received on a participating port.
func (b *stpBridge) handleBPDU(src *portEntry, frame []byte) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if !b.cfg.Enabled {
		return
	}
	sp := b.ports[src.id]
	if sp == nil {
		return
	}

	body := frame[ethHeaderLen+3:] // past LLC
	if len(body) < 4 {
		return
	}
	bpduType := body[3]

	if bpduType == 0x80 { // TCN
		// Designated bridge on the segment: acknowledge and propagate.
		b.sw.mu.Lock()
		if sp.role == "designated" {
			b.signalTopologyChangeLocked()
			sp.entry.port.Send(Meta{SrcPortID: "stp"}, b.buildConfig(sp, 0x80 /* TCA */))
		}
		b.sw.mu.Unlock()
		return
	}
	if bpduType != 0x00 || len(body) < 35 {
		return
	}

	info := priorityVector{
		rootID:   binary.BigEndian.Uint64(body[5:13]),
		cost:     binary.BigEndian.Uint32(body[13:17]),
		bridgeID: binary.BigEndian.Uint64(body[17:25]),
		portID:   binary.BigEndian.Uint16(body[25:27]),
	}
	flags := body[4]

	b.sw.mu.Lock()
	// Store if better than (or refreshing) what we hold for the segment.
	refresh := sp.hasInfo && info.bridgeID == sp.info.bridgeID && info.portID == sp.info.portID
	if !sp.hasInfo || refresh || info.better(sp.info) {
		sp.hasInfo = true
		sp.info = info
		sp.infoAge = time.Duration(binary.BigEndian.Uint16(body[27:29])) * time.Second / 256
		b.recomputeLocked()
	}
	// Topology-change flag from the root: fast-age the FDB.
	if flags&0x01 != 0 {
		b.sw.fdb.flush("", nil)
	}
	// TCA from upstream clears our pending TCN.
	if flags&0x80 != 0 && src.id == b.rootPort {
		b.tcnPending = false
	}
	b.sw.mu.Unlock()
}

// --- BPDU encoding ---

var bpduDstMAC = []byte{0x01, 0x80, 0xc2, 0x00, 0x00, 0x00}

func (b *stpBridge) frameHeader(payloadLen int) []byte {
	f := make([]byte, ethHeaderLen+3+payloadLen)
	copy(f[0:6], bpduDstMAC)
	f[6] = 0x02 // bridge MAC as source
	copy(f[7:12], b.mac[1:6])
	binary.BigEndian.PutUint16(f[12:14], uint16(3+payloadLen)) // 802.3 length
	f[14], f[15], f[16] = 0x42, 0x42, 0x03                     // LLC STP SAP, UI
	return f
}

func (b *stpBridge) buildConfig(sp *stpPort, flags byte) []byte {
	f := b.frameHeader(35)
	p := f[ethHeaderLen+3:]
	// protocol id (0), version (0), type (0) already zero.
	p[4] = flags
	binary.BigEndian.PutUint64(p[5:13], b.rootID)
	binary.BigEndian.PutUint32(p[13:17], b.rootCost)
	binary.BigEndian.PutUint64(p[17:25], b.bridgeID())
	binary.BigEndian.PutUint16(p[25:27], sp.portIDValue())
	age := time.Duration(0)
	if b.rootPort != "" {
		if rp := b.ports[b.rootPort]; rp != nil {
			age = rp.infoAge + time.Second
		}
	}
	binary.BigEndian.PutUint16(p[27:29], uint16(age*256/time.Second))
	binary.BigEndian.PutUint16(p[29:31], uint16(b.cfg.MaxAge*256/time.Second))
	binary.BigEndian.PutUint16(p[31:33], uint16(b.cfg.HelloTime*256/time.Second))
	binary.BigEndian.PutUint16(p[33:35], uint16(b.cfg.ForwardDelay*256/time.Second))
	// Pad to minimum ethernet frame.
	if len(f) < 60 {
		f = append(f, make([]byte, 60-len(f))...)
	}
	return f
}

func (b *stpBridge) buildTCN() []byte {
	f := b.frameHeader(4)
	f[ethHeaderLen+3+3] = 0x80 // type TCN
	if len(f) < 60 {
		f = append(f, make([]byte, 60-len(f))...)
	}
	return f
}

// runAsync runs fn on a fresh goroutine (used to escape lock contexts).
func (s *Switch) runAsync(fn func()) {
	go fn()
}
