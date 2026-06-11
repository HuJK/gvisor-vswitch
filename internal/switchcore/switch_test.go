package switchcore

import (
	"encoding/binary"
	"net"
	"sync"
	"testing"
	"time"
)

// fakePort records frames sent to it.
type fakePort struct {
	id string

	mu     sync.Mutex
	frames [][]byte
	metas  []Meta
}

func (p *fakePort) ID() string { return p.id }
func (p *fakePort) Send(meta Meta, frame []byte) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.frames = append(p.frames, frame)
	p.metas = append(p.metas, meta)
	return true
}
func (p *fakePort) Close() error { return nil }

func (p *fakePort) take() [][]byte {
	p.mu.Lock()
	defer p.mu.Unlock()
	out := p.frames
	p.frames = nil
	p.metas = nil
	return out
}

func mac(s string) net.HardwareAddr {
	m, err := net.ParseMAC(s)
	if err != nil {
		panic(err)
	}
	return m
}

// frame builds an ethernet frame; vid < 0 means untagged.
func frame(dst, src net.HardwareAddr, vid int, payload ...byte) []byte {
	f := make([]byte, 0, 64)
	f = append(f, dst...)
	f = append(f, src...)
	if vid >= 0 {
		tag := make([]byte, 4)
		binary.BigEndian.PutUint16(tag[0:2], etherTypeVLAN)
		binary.BigEndian.PutUint16(tag[2:4], uint16(vid))
		f = append(f, tag...)
	}
	f = append(f, 0x08, 0x00) // IPv4 ethertype
	f = append(f, payload...)
	for len(f) < 60 {
		f = append(f, 0)
	}
	return f
}

var (
	macA  = mac("02:00:00:00:00:0a")
	macB  = mac("02:00:00:00:00:0b")
	macC  = mac("02:00:00:00:00:0c")
	bcast = mac("ff:ff:ff:ff:ff:ff")
)

func newTestSwitch(t *testing.T, attrs map[string]PortAttrs) (*Switch, map[string]*fakePort) {
	t.Helper()
	sw := New()
	t.Cleanup(sw.Close)
	ports := make(map[string]*fakePort)
	for id, a := range attrs {
		p := &fakePort{id: id}
		if err := sw.AddPort(p, a); err != nil {
			t.Fatalf("AddPort(%s): %v", id, err)
		}
		ports[id] = p
	}
	return sw, ports
}

func TestFloodAndLearnThenUnicast(t *testing.T) {
	sw, p := newTestSwitch(t, map[string]PortAttrs{
		"p1": {VLAN: VLANTrunk},
		"p2": {VLAN: VLANTrunk},
		"p3": {VLAN: VLANTrunk},
	})

	// Unknown dst from p1: flood to p2, p3, not back to p1.
	sw.Deliver("p1", frame(macB, macA, -1))
	if got := len(p["p2"].take()); got != 1 {
		t.Errorf("p2 flood: got %d frames, want 1", got)
	}
	if got := len(p["p3"].take()); got != 1 {
		t.Errorf("p3 flood: got %d frames, want 1", got)
	}
	if got := len(p["p1"].take()); got != 0 {
		t.Errorf("p1 echo: got %d frames, want 0", got)
	}

	// Reply from p2: macA was learned on p1 -> unicast.
	sw.Deliver("p2", frame(macA, macB, -1))
	if got := len(p["p1"].take()); got != 1 {
		t.Errorf("p1 unicast: got %d frames, want 1", got)
	}
	if got := len(p["p3"].take()); got != 0 {
		t.Errorf("p3 leak: got %d frames, want 0", got)
	}

	// Now macB is learned on p2.
	sw.Deliver("p1", frame(macB, macA, -1))
	if got := len(p["p2"].take()); got != 1 {
		t.Errorf("p2 unicast: got %d frames, want 1", got)
	}
	if got := len(p["p3"].take()); got != 0 {
		t.Errorf("p3 leak: got %d frames, want 0", got)
	}
}

func TestAccessVLANSeparation(t *testing.T) {
	sw, p := newTestSwitch(t, map[string]PortAttrs{
		"v10a": {VLAN: 10},
		"v10b": {VLAN: 10},
		"v20":  {VLAN: 20},
	})

	sw.Deliver("v10a", frame(bcast, macA, -1))
	if got := len(p["v10b"].take()); got != 1 {
		t.Errorf("v10b: got %d frames, want 1", got)
	}
	if got := len(p["v20"].take()); got != 0 {
		t.Errorf("v20 cross-vlan leak: got %d frames, want 0", got)
	}

	// Tagged frame into an access port is dropped.
	sw.Deliver("v10a", frame(bcast, macA, 10))
	if got := len(p["v10b"].take()); got != 0 {
		t.Errorf("tagged-on-access: got %d frames, want 0", got)
	}
}

func TestAccessTrunkTagRewrite(t *testing.T) {
	sw, p := newTestSwitch(t, map[string]PortAttrs{
		"acc":   {VLAN: 10},
		"trunk": {VLAN: VLANTrunk},
	})

	// access -> trunk: tag inserted.
	sw.Deliver("acc", frame(bcast, macA, -1))
	out := p["trunk"].take()
	if len(out) != 1 {
		t.Fatalf("trunk: got %d frames, want 1", len(out))
	}
	fv, ok := parseFrame(out[0])
	if !ok || !fv.tagged || fv.vid != 10 {
		t.Errorf("trunk frame: tagged=%v vid=%d, want tagged vid=10", fv.tagged, fv.vid)
	}

	// trunk -> access: tag stripped.
	sw.Deliver("trunk", frame(bcast, macB, 10))
	out = p["acc"].take()
	if len(out) != 1 {
		t.Fatalf("acc: got %d frames, want 1", len(out))
	}
	fv, ok = parseFrame(out[0])
	if !ok || fv.tagged {
		t.Errorf("acc frame still tagged")
	}

	// trunk vlan 20 -> access vlan 10: dropped.
	sw.Deliver("trunk", frame(bcast, macB, 20))
	if got := len(p["acc"].take()); got != 0 {
		t.Errorf("acc cross-vlan: got %d frames, want 0", got)
	}
}

func TestUntaggedOnlyAndTrunkUntaggedDomain(t *testing.T) {
	sw, p := newTestSwitch(t, map[string]PortAttrs{
		"u":     {VLAN: VLANUntaggedOnly}, // 0
		"trunk": {VLAN: VLANTrunk},        // 4095
		"acc10": {VLAN: 10},
	})

	// Untagged from u reaches trunk untagged, never the access vlan.
	sw.Deliver("u", frame(bcast, macA, -1))
	out := p["trunk"].take()
	if len(out) != 1 {
		t.Fatalf("trunk: got %d frames, want 1", len(out))
	}
	if fv, _ := parseFrame(out[0]); fv.tagged {
		t.Errorf("trunk frame tagged, want untagged domain frame untagged")
	}
	if got := len(p["acc10"].take()); got != 0 {
		t.Errorf("acc10: got %d frames, want 0", got)
	}

	// Tagged into u is dropped.
	sw.Deliver("u", frame(bcast, macA, 5))
	if got := len(p["trunk"].take()); got != 0 {
		t.Errorf("tagged-on-u: got %d frames, want 0", got)
	}

	// A VID-0 (priority) tag from trunk is the untagged domain: u gets it,
	// untagged; acc10 does not.
	sw.Deliver("trunk", frame(bcast, macB, 0))
	out = p["u"].take()
	if len(out) != 1 {
		t.Fatalf("u: got %d frames, want 1 (vid-0 tag = untagged domain)", len(out))
	}
	if fv, _ := parseFrame(out[0]); fv.tagged {
		t.Errorf("u received tagged frame, want priority tag stripped")
	}
	if got := len(p["acc10"].take()); got != 0 {
		t.Errorf("acc10: got %d frames, want 0", got)
	}

	// Tagged vlan 10 from trunk reaches only the access port.
	sw.Deliver("trunk", frame(bcast, macB, 10))
	if got := len(p["u"].take()); got != 0 {
		t.Errorf("u got vlan-10 frame, want 0")
	}
	if got := len(p["acc10"].take()); got != 1 {
		t.Errorf("acc10: got %d frames, want 1", got)
	}
}

func TestIsolation(t *testing.T) {
	sw, p := newTestSwitch(t, map[string]PortAttrs{
		"iso1": {VLAN: VLANTrunk, Isolated: true},
		"iso2": {VLAN: VLANTrunk, Isolated: true},
		"open": {VLAN: VLANTrunk},
	})

	sw.Deliver("iso1", frame(bcast, macA, -1))
	if got := len(p["iso2"].take()); got != 0 {
		t.Errorf("iso2: got %d frames, want 0", got)
	}
	if got := len(p["open"].take()); got != 1 {
		t.Errorf("open: got %d frames, want 1", got)
	}

	sw.Deliver("open", frame(bcast, macC, -1))
	if got := len(p["iso1"].take()); got != 1 {
		t.Errorf("iso1 from open: got %d frames, want 1", got)
	}
}

func TestPortSecurity(t *testing.T) {
	sw, p := newTestSwitch(t, map[string]PortAttrs{
		"sec":  {VLAN: VLANTrunk, SecurityMAC: macA},
		"peer": {VLAN: VLANTrunk},
	})

	sw.Deliver("sec", frame(bcast, macB, -1)) // wrong src mac
	if got := len(p["peer"].take()); got != 0 {
		t.Errorf("peer: got %d frames, want 0 (port-security)", got)
	}
	sw.Deliver("sec", frame(bcast, macA, -1))
	if got := len(p["peer"].take()); got != 1 {
		t.Errorf("peer: got %d frames, want 1", got)
	}
}

func TestFDBAgingAndFlush(t *testing.T) {
	f := newFDB(100 * time.Millisecond)
	now := time.Now()
	f.now = func() time.Time { return now }

	var m [6]byte
	copy(m[:], macA)
	p1 := &portEntry{id: "p1"}
	f.learn(5, m, p1)
	if _, got := f.lookup(5, m); got != "p1" {
		t.Fatalf("lookup: got %q, want p1", got)
	}

	now = now.Add(200 * time.Millisecond)
	if _, got := f.lookup(5, m); got != "" {
		t.Errorf("expired lookup: got %q, want miss", got)
	}
	f.expire()
	if n := len(f.snapshot()); n != 0 {
		t.Errorf("snapshot after expire: %d entries, want 0", n)
	}

	now = now.Add(time.Millisecond)
	f.learn(5, m, p1)
	f.flushPort("p1")
	if _, got := f.lookup(5, m); got != "" {
		t.Errorf("flushed lookup: got %q, want miss", got)
	}
}

func TestPortDownEventAndFDBFlush(t *testing.T) {
	sw, p := newTestSwitch(t, map[string]PortAttrs{
		"p1": {VLAN: VLANTrunk},
		"p2": {VLAN: VLANTrunk},
	})

	var downs []string
	sw.OnPortDown(func(id string) { downs = append(downs, id) })

	sw.Deliver("p1", frame(macB, macA, -1))
	p["p2"].take()

	sw.NotifyDown("p1")
	if len(downs) != 1 || downs[0] != "p1" {
		t.Errorf("downs = %v, want [p1]", downs)
	}
	// macA must be flushed: frame to macA floods again.
	sw.Deliver("p2", frame(macA, macB, -1))
	if got := len(p["p1"].take()); got != 1 {
		t.Errorf("p1: got %d frames, want 1 (flood after flush)", got)
	}

	sw.RemovePort("p1")
	if len(downs) != 2 || downs[1] != "p1" {
		t.Errorf("downs = %v, want [p1 p1]", downs)
	}
	if _, ok := sw.PortAttrs("p1"); ok {
		t.Errorf("p1 still registered after RemovePort")
	}
}

func TestMetaCarriesSourcePort(t *testing.T) {
	sw, p := newTestSwitch(t, map[string]PortAttrs{
		"vm1": {VLAN: 10},
		"gw":  {VLAN: 10},
	})
	sw.Deliver("vm1", frame(bcast, macA, -1))
	gw := p["gw"]
	gw.mu.Lock()
	defer gw.mu.Unlock()
	if len(gw.metas) != 1 || gw.metas[0].SrcPortID != "vm1" {
		t.Errorf("meta = %+v, want SrcPortID=vm1", gw.metas)
	}
}

func TestStaticFDB(t *testing.T) {
	sw, p := newTestSwitch(t, map[string]PortAttrs{
		"p1": {VLAN: VLANTrunk},
		"p2": {VLAN: VLANTrunk},
		"p3": {VLAN: VLANTrunk},
	})

	// Static entry on the untagged domain (trunk ports exchange untagged
	// frames there): unicast to macC goes straight to p3 without learning.
	if err := sw.AddStaticFDB(0, macC, "p3"); err != nil {
		t.Fatal(err)
	}
	sw.Deliver("p1", frame(macC, macA, -1))
	if got := len(p["p3"].take()); got != 1 {
		t.Errorf("p3: got %d frames, want 1 (static entry)", got)
	}
	if got := len(p["p2"].take()); got != 0 {
		t.Errorf("p2: got %d frames, want 0 (no flood)", got)
	}

	// Learning must not override the static entry: macC talks from p2,
	// but traffic to macC still goes to p3.
	sw.Deliver("p2", frame(bcast, macC, -1))
	p["p1"].take()
	p["p3"].take()
	sw.Deliver("p1", frame(macC, macA, -1))
	if got := len(p["p3"].take()); got != 1 {
		t.Errorf("p3 after learn attempt: got %d frames, want 1", got)
	}
	if got := len(p["p2"].take()); got != 0 {
		t.Errorf("p2 stole static traffic: got %d frames", got)
	}

	// Dynamic delete refuses static entries.
	if err := sw.DeleteFDBEntry(0, macC); err == nil {
		t.Error("DeleteFDBEntry deleted a static entry")
	}

	// Static entries survive port-down flushes and flush-all.
	sw.NotifyDown("p3")
	sw.FlushFDB("", nil)
	rows := sw.FDB()
	if len(rows) != 1 || !rows[0].Static || rows[0].PortID != "p3" {
		t.Fatalf("fdb after flush = %+v, want only the static entry", rows)
	}

	if err := sw.RemoveStaticFDB(0, macC); err != nil {
		t.Fatal(err)
	}
	if len(sw.FDB()) != 0 {
		t.Error("static entry still present after removal")
	}

	// Validation: 4095 (trunk) is not a forwarding domain.
	if err := sw.AddStaticFDB(4095, macC, "p3"); err == nil {
		t.Error("vlan 4095 accepted for static fdb")
	}
	if err := sw.AddStaticFDB(0, bcast, "p3"); err == nil {
		t.Error("multicast MAC accepted for static fdb")
	}
}

func TestDisabledPort(t *testing.T) {
	sw, p := newTestSwitch(t, map[string]PortAttrs{
		"up":   {VLAN: VLANTrunk},
		"down": {VLAN: VLANTrunk, Disabled: true},
		"peer": {VLAN: VLANTrunk},
	})

	// Ingress on a disabled port is dropped.
	sw.Deliver("down", frame(bcast, macA, -1))
	if got := len(p["peer"].take()); got != 0 {
		t.Errorf("peer got %d frames from disabled port", got)
	}

	// Egress to a disabled port is skipped.
	sw.Deliver("up", frame(bcast, macB, -1))
	if got := len(p["down"].take()); got != 0 {
		t.Errorf("disabled port got %d frames", got)
	}
	if got := len(p["peer"].take()); got != 1 {
		t.Errorf("peer: got %d frames, want 1", got)
	}

	// Re-enable via UpdatePortAttrs.
	if err := sw.UpdatePortAttrs("down", PortAttrs{VLAN: VLANTrunk}); err != nil {
		t.Fatal(err)
	}
	sw.Deliver("up", frame(bcast, macB, -1))
	if got := len(p["down"].take()); got != 1 {
		t.Errorf("re-enabled port: got %d frames, want 1", got)
	}
}

func TestPortCounters(t *testing.T) {
	sw, _ := newTestSwitch(t, map[string]PortAttrs{
		"p1": {VLAN: VLANTrunk},
		"p2": {VLAN: 10}, // different vlan: p1's frames are dropped at p2 egress check
	})

	f := frame(bcast, macA, -1)
	sw.Deliver("p1", f)

	st, ok := sw.PortStats("p1")
	if !ok || st.RxFrames != 1 || st.RxBytes != uint64(len(f)) {
		t.Errorf("p1 stats = %+v", st)
	}
	// Nothing was eligible: no tx counted anywhere.
	st2, _ := sw.PortStats("p2")
	if st2.TxFrames != 0 {
		t.Errorf("p2 tx = %d, want 0", st2.TxFrames)
	}

	// Same vlan: tx counted at the destination.
	sw.UpdatePortAttrs("p2", PortAttrs{VLAN: VLANTrunk})
	sw.Deliver("p1", frame(bcast, macA, -1))
	st2, _ = sw.PortStats("p2")
	if st2.TxFrames != 1 {
		t.Errorf("p2 tx = %d, want 1", st2.TxFrames)
	}

	// Security drop counts as rx_dropped.
	sw.UpdatePortAttrs("p1", PortAttrs{VLAN: VLANTrunk, SecurityMAC: macB})
	sw.Deliver("p1", frame(bcast, macA, -1))
	st, _ = sw.PortStats("p1")
	if st.RxDropped != 1 {
		t.Errorf("p1 rx_dropped = %d, want 1", st.RxDropped)
	}
}

func TestFDBFlushFiltersAndAging(t *testing.T) {
	sw, p := newTestSwitch(t, map[string]PortAttrs{
		"p1": {VLAN: 10},
		"p2": {VLAN: 20},
	})
	_ = p
	sw.Deliver("p1", frame(bcast, macA, -1))
	sw.Deliver("p2", frame(bcast, macB, -1))
	if got := len(sw.FDB()); got != 2 {
		t.Fatalf("fdb = %d entries, want 2", got)
	}

	v := 10
	if n := sw.FlushFDB("", &v); n != 1 {
		t.Errorf("flush vlan 10 removed %d, want 1", n)
	}
	if n := sw.FlushFDB("p2", nil); n != 1 {
		t.Errorf("flush port p2 removed %d, want 1", n)
	}

	if err := sw.SetFDBMaxAge(0); err == nil {
		t.Error("zero aging accepted")
	}
	if err := sw.SetFDBMaxAge(42 * time.Second); err != nil {
		t.Fatal(err)
	}
	if got := sw.FDBMaxAge(); got != 42*time.Second {
		t.Errorf("max age = %v", got)
	}
}

func TestStaticFDBTargetPortRemovedAndRecreated(t *testing.T) {
	sw, p := newTestSwitch(t, map[string]PortAttrs{
		"src": {VLAN: VLANTrunk},
		"p3":  {VLAN: VLANTrunk},
	})
	if err := sw.AddStaticFDB(0, macC, "p3"); err != nil {
		t.Fatal(err)
	}

	// Baseline: static entry forwards to p3.
	sw.Deliver("src", frame(macC, macA, -1))
	if got := len(p["p3"].take()); got != 1 {
		t.Fatalf("p3: got %d frames, want 1", got)
	}

	// Target port removed: the static entry must black-hole (no panic,
	// no flood back to other ports), and survive in the FDB.
	sw.RemovePort("p3")
	sw.Deliver("src", frame(macC, macA, -1))
	if got := len(p["p3"].take()); got != 0 {
		t.Errorf("removed p3 got %d frames", got)
	}
	foundStatic := false
	for _, row := range sw.FDB() {
		if row.Static && row.PortID == "p3" {
			foundStatic = true
		}
	}
	if !foundStatic {
		t.Fatal("static entry lost after port removal")
	}

	// Port recreated under the same ID: forwarding resumes on the next
	// frame, no invalidation step needed.
	p3b := &fakePort{id: "p3"}
	if err := sw.AddPort(p3b, PortAttrs{VLAN: VLANTrunk}); err != nil {
		t.Fatal(err)
	}
	sw.Deliver("src", frame(macC, macA, -1))
	if got := len(p3b.take()); got != 1 {
		t.Fatalf("recreated p3: got %d frames, want 1", got)
	}
}

func TestPortRefSurvivesRecreation(t *testing.T) {
	sw, p := newTestSwitch(t, map[string]PortAttrs{
		"src": {VLAN: VLANTrunk},
		"dst": {VLAN: VLANTrunk},
	})

	ref := sw.Ref("src")
	ref.Deliver(frame(bcast, macA, -1)) // resolves + caches
	if got := len(p["dst"].take()); got != 1 {
		t.Fatalf("dst: got %d frames, want 1", got)
	}

	// Source port removed: cached pointer is gone-flagged, deliveries
	// drop silently.
	sw.RemovePort("src")
	ref.Deliver(frame(bcast, macA, -1))
	if got := len(p["dst"].take()); got != 0 {
		t.Errorf("dst got %d frames from removed src", got)
	}

	// Recreated under the same ID: the ref re-resolves to the new entry.
	srcB := &fakePort{id: "src"}
	if err := sw.AddPort(srcB, PortAttrs{VLAN: VLANTrunk}); err != nil {
		t.Fatal(err)
	}
	ref.Deliver(frame(bcast, macA, -1))
	if got := len(p["dst"].take()); got != 1 {
		t.Fatalf("dst after recreation: got %d frames, want 1", got)
	}
}
