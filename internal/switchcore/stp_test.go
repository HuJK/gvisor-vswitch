package switchcore

import (
	"encoding/binary"
	"sync"
	"testing"
	"time"
)

// --- protection primitives ---

// minimalBPDU builds a syntactically valid config BPDU frame.
func minimalBPDU() []byte {
	f := make([]byte, 60)
	copy(f[0:6], bpduDstMAC)
	copy(f[6:12], []byte{0x02, 0, 0, 0, 0, 0x42})
	binary.BigEndian.PutUint16(f[12:14], 38) // 802.3 length
	f[14], f[15], f[16] = 0x42, 0x42, 0x03
	return f
}

func TestReservedMACNeverForwarded(t *testing.T) {
	sw, p := newTestSwitch(t, map[string]PortAttrs{
		"p1": {VLAN: VLANTrunk},
		"p2": {VLAN: VLANTrunk},
	})
	// BPDU (STP off, no guard): consumed silently.
	sw.Deliver("p1", minimalBPDU())
	// Another reserved address (01:80:C2:00:00:0E, LLDP): also consumed.
	lldp := frame(mac("01:80:c2:00:00:0e"), macA, -1)
	sw.Deliver("p1", lldp)
	if got := len(p["p2"].take()); got != 0 {
		t.Fatalf("p2 received %d reserved-group frames, want 0", got)
	}
}

func TestBPDUGuard(t *testing.T) {
	sw, p := newTestSwitch(t, map[string]PortAttrs{
		"vm":   {VLAN: VLANTrunk, BPDUGuard: true},
		"peer": {VLAN: VLANTrunk},
	})

	sw.Deliver("vm", minimalBPDU())
	if reason := sw.BlockReason("vm"); reason != "bpdu_guard" {
		t.Fatalf("block reason = %q, want bpdu_guard", reason)
	}
	attrs, _ := sw.PortAttrs("vm")
	if !attrs.Disabled {
		t.Fatal("port not disabled by bpdu guard")
	}
	// Disabled: normal traffic dropped.
	sw.Deliver("vm", frame(bcast, macA, -1))
	if got := len(p["peer"].take()); got != 0 {
		t.Errorf("guarded port still forwards: %d frames", got)
	}

	// Re-enabling clears the reason.
	attrs.Disabled = false
	if err := sw.UpdatePortAttrs("vm", attrs); err != nil {
		t.Fatal(err)
	}
	if reason := sw.BlockReason("vm"); reason != "" {
		t.Errorf("block reason after re-enable = %q", reason)
	}
}

func TestStormControl(t *testing.T) {
	sw, p := newTestSwitch(t, map[string]PortAttrs{
		"src": {VLAN: VLANTrunk, StormPPS: 10},
		"dst": {VLAN: VLANTrunk},
	})

	for i := 0; i < 200; i++ {
		sw.Deliver("src", frame(bcast, macA, -1))
	}
	got := len(p["dst"].take())
	if got > 25 { // bucket allows ~pps within the burst window
		t.Fatalf("storm control passed %d flooded frames, want <=25", got)
	}
	st, _ := sw.PortStats("src")
	if st.StormDropped == 0 {
		t.Fatal("storm_dropped not counted")
	}

	// Known unicast is not storm-limited.
	sw.Deliver("dst", frame(macA, macB, -1)) // learn macB@dst? actually teaches macB
	sw.Deliver("dst", frame(macA, macB, -1))
	p["src"].take()
	for i := 0; i < 50; i++ {
		sw.Deliver("src", frame(macB, macA, -1))
	}
	if got := len(p["dst"].take()); got != 50 {
		t.Fatalf("known unicast limited: got %d, want 50", got)
	}
}

// wirePort simulates a cable between two switches: Send on one side
// asynchronously delivers into the peer switch.
type wirePort struct {
	id   string
	peer func(frame []byte)
	mu   sync.Mutex
	down bool
}

func (w *wirePort) ID() string { return w.id }
func (w *wirePort) Send(_ Meta, frame []byte) bool {
	w.mu.Lock()
	down := w.down
	peer := w.peer
	w.mu.Unlock()
	if down || peer == nil {
		return false
	}
	go peer(frame)
	return true
}
func (w *wirePort) Close() error { return nil }
func (w *wirePort) cut() {
	w.mu.Lock()
	w.down = true
	w.mu.Unlock()
}

// link connects swA.portA <-> swB.portB with STP-participating ports.
func link(t *testing.T, swA *Switch, portA string, swB *Switch, portB string, cost uint32) (*wirePort, *wirePort) {
	t.Helper()
	a := &wirePort{id: portA}
	bp := &wirePort{id: portB}
	refA := swA.Ref(portA)
	refB := swB.Ref(portB)
	a.peer = func(f []byte) { refB.Deliver(f) }
	bp.peer = func(f []byte) { refA.Deliver(f) }
	attrs := PortAttrs{VLAN: VLANTrunk, STP: true, STPCost: cost}
	if err := swA.AddPort(a, attrs); err != nil {
		t.Fatal(err)
	}
	if err := swB.AddPort(bp, attrs); err != nil {
		t.Fatal(err)
	}
	return a, bp
}

func fastSTP(t *testing.T, sw *Switch, prio uint16) {
	t.Helper()
	if err := sw.SetSTPConfig(STPConfig{
		Enabled:      true,
		Priority:     prio,
		HelloTime:    50 * time.Millisecond,
		MaxAge:       400 * time.Millisecond,
		ForwardDelay: 100 * time.Millisecond,
	}); err != nil {
		t.Fatal(err)
	}
}

// waitConverged waits until the four link ports settle into exactly one
// blocking port with the rest forwarding.
func waitConverged(t *testing.T, sws []*Switch, want map[string]int) map[string]string {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		states := map[string]string{}
		counts := map[string]int{}
		for _, sw := range sws {
			_, ports := sw.STPStatus()
			for id, st := range ports {
				states[id] = st.State
				counts[st.State]++
			}
		}
		ok := true
		for state, n := range want {
			if counts[state] != n {
				ok = false
			}
		}
		if ok {
			return states
		}
		if time.Now().After(deadline) {
			t.Fatalf("never converged: %v", states)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func TestSTPBlocksRedundantLink(t *testing.T) {
	swA := New()
	swB := New()
	t.Cleanup(swA.Close)
	t.Cleanup(swB.Close)

	// Leaf capture ports on both switches.
	leafA := &fakePort{id: "leafA"}
	leafB := &fakePort{id: "leafB"}
	swA.AddPort(leafA, PortAttrs{VLAN: VLANTrunk})
	swB.AddPort(leafB, PortAttrs{VLAN: VLANTrunk})

	// Two parallel links = a loop.
	link(t, swA, "a1", swB, "b1", 100)
	link(t, swA, "a2", swB, "b2", 100)

	fastSTP(t, swA, 4096) // lower priority -> root
	fastSTP(t, swB, 32768)

	// Exactly one of the four link ports must end up blocking.
	states := waitConverged(t, []*Switch{swA, swB}, map[string]int{"blocking": 1, "forwarding": 3})

	// The root bridge is A (lower priority); all of A's ports forward, so
	// the blocked port is on B.
	stA, _ := swA.STPStatus()
	stB, _ := swB.STPStatus()
	if !stA.IsRoot || stB.IsRoot {
		t.Fatalf("root election wrong: A=%+v B=%+v", stA, stB)
	}
	if states["a1"] != "forwarding" || states["a2"] != "forwarding" {
		t.Fatalf("root bridge has non-forwarding port: %v", states)
	}

	// A broadcast from leafA arrives at leafB exactly once (no storm, no
	// duplication through the redundant link).
	time.Sleep(100 * time.Millisecond)
	swA.Deliver("leafA", frame(bcast, macA, -1))
	time.Sleep(200 * time.Millisecond)
	if got := len(leafB.take()); got != 1 {
		t.Fatalf("leafB got %d copies, want exactly 1", got)
	}
}

func TestSTPFailover(t *testing.T) {
	swA := New()
	swB := New()
	t.Cleanup(swA.Close)
	t.Cleanup(swB.Close)

	a1, b1 := link(t, swA, "a1", swB, "b1", 100)
	link(t, swA, "a2", swB, "b2", 200) // higher cost: the backup

	fastSTP(t, swA, 4096)
	fastSTP(t, swB, 32768)

	states := waitConverged(t, []*Switch{swA, swB}, map[string]int{"blocking": 1, "forwarding": 3})
	if states["b2"] != "blocking" {
		t.Fatalf("expected b2 (higher cost) blocked, got %v", states)
	}

	// Cut the primary link: BPDUs stop, info ages out, the backup must
	// move to forwarding.
	a1.cut()
	b1.cut()

	deadline := time.Now().Add(5 * time.Second)
	for {
		_, ports := swB.STPStatus()
		if ports["b2"].State == "forwarding" {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("backup never took over: %v", ports)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func TestSTPDisabledLeavesPortsForwarding(t *testing.T) {
	sw, p := newTestSwitch(t, map[string]PortAttrs{
		"p1": {VLAN: VLANTrunk, STP: true},
		"p2": {VLAN: VLANTrunk},
	})
	// Bridge STP disabled: the stp flag alone must not gate traffic.
	sw.Deliver("p1", frame(bcast, macA, -1))
	if got := len(p["p2"].take()); got != 1 {
		t.Fatalf("p2 got %d frames, want 1", got)
	}
}

// loopWire wires two ports of the SAME switch together (a real cable
// loop): egress of one is delivered as ingress of the other.
func loopWire(t *testing.T, sw *Switch, idA, idB string, attrs PortAttrs) {
	t.Helper()
	a := &wirePort{id: idA}
	b := &wirePort{id: idB}
	refA := sw.Ref(idA)
	refB := sw.Ref(idB)
	a.peer = func(f []byte) { refB.Deliver(f) }
	b.peer = func(f []byte) { refA.Deliver(f) }
	if err := sw.AddPort(a, attrs); err != nil {
		t.Fatal(err)
	}
	if err := sw.AddPort(b, attrs); err != nil {
		t.Fatal(err)
	}
}

func TestLoopProbeBlocksLoopedPort(t *testing.T) {
	sw := New()
	t.Cleanup(sw.Close)
	sw.SetLoopProbeInterval(30 * time.Millisecond)

	// Storm control keeps the loop from melting the test before the
	// probe catches it.
	loopWire(t, sw, "upA", "upB", PortAttrs{
		VLAN: VLANTrunk, LoopDetect: true, StormPPS: 50,
	})

	deadline := time.Now().Add(3 * time.Second)
	for {
		a, b := sw.BlockReason("upA"), sw.BlockReason("upB")
		if a == "loop" || b == "loop" {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("loop never detected (reasons %q/%q)", a, b)
		}
		time.Sleep(10 * time.Millisecond)
	}
}
