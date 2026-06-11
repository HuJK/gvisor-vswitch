package ports

import (
	"bytes"
	"encoding/binary"
	"net"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/HuJK/gvisor-vswitch/internal/switchcore"
)

// capturePort records frames the switch sends it.
type capturePort struct {
	id string
	mu sync.Mutex
	fr [][]byte
}

func (p *capturePort) ID() string { return p.id }
func (p *capturePort) Send(_ switchcore.Meta, frame []byte) bool {
	p.mu.Lock()
	p.fr = append(p.fr, frame)
	p.mu.Unlock()
	return true
}
func (p *capturePort) Close() error { return nil }

func (p *capturePort) waitFrames(t *testing.T, n int) [][]byte {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for {
		p.mu.Lock()
		if len(p.fr) >= n {
			out := p.fr
			p.mu.Unlock()
			return out
		}
		p.mu.Unlock()
		if time.Now().After(deadline) {
			t.Fatalf("timeout waiting for %d frames", n)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func testFrame(b byte) []byte {
	f := make([]byte, 60)
	copy(f[0:6], []byte{0x02, 0, 0, 0, 0, 0x01})  // dst
	copy(f[6:12], []byte{0x02, 0, 0, 0, 0, 0x02}) // src
	f[12], f[13] = 0x08, 0x00
	f[14] = b
	return f
}

func writeStreamFrame(t *testing.T, conn net.Conn, frame []byte) {
	t.Helper()
	buf := make([]byte, 4+len(frame))
	binary.BigEndian.PutUint32(buf, uint32(len(frame)))
	copy(buf[4:], frame)
	if _, err := conn.Write(buf); err != nil {
		t.Fatalf("write frame: %v", err)
	}
}

func readStreamFrame(t *testing.T, conn net.Conn) []byte {
	t.Helper()
	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	hdr := make([]byte, 4)
	if _, err := readFull(conn, hdr); err != nil {
		t.Fatalf("read header: %v", err)
	}
	buf := make([]byte, binary.BigEndian.Uint32(hdr))
	if _, err := readFull(conn, buf); err != nil {
		t.Fatalf("read body: %v", err)
	}
	return buf
}

func readFull(conn net.Conn, buf []byte) (int, error) {
	n := 0
	for n < len(buf) {
		m, err := conn.Read(buf[n:])
		n += m
		if err != nil {
			return n, err
		}
	}
	return n, nil
}

func newSwitchWithCapture(t *testing.T) (*switchcore.Switch, *capturePort) {
	t.Helper()
	sw := switchcore.New()
	t.Cleanup(sw.Close)
	cap := &capturePort{id: "cap"}
	if err := sw.AddPort(cap, switchcore.PortAttrs{VLAN: switchcore.VLANTrunk}); err != nil {
		t.Fatal(err)
	}
	return sw, cap
}

func TestStreamClientPort(t *testing.T) {
	sw, cap := newSwitchWithCapture(t)

	path := filepath.Join(t.TempDir(), "srv.sock")
	ln, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	connCh := make(chan net.Conn, 1)
	go func() {
		c, err := ln.Accept()
		if err == nil {
			connCh <- c
		}
	}()

	p, err := NewClient(sw, ClientConfig{ID: "c1", Transport: "unix", Remote: path})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	if err := sw.AddPort(p, switchcore.PortAttrs{VLAN: switchcore.VLANTrunk}); err != nil {
		t.Fatal(err)
	}
	peer := <-connCh

	// VM -> switch: frame arrives at the capture port.
	writeStreamFrame(t, peer, testFrame(0xaa))
	got := cap.waitFrames(t, 1)
	if got[0][14] != 0xaa {
		t.Errorf("frame payload = %x, want aa", got[0][14])
	}

	// switch -> VM: deliver from capture port, flood reaches client.
	sw.Deliver("cap", testFrame(0xbb))
	out := readStreamFrame(t, peer)
	if out[14] != 0xbb {
		t.Errorf("frame payload = %x, want bb", out[14])
	}

	if st := p.Status(); !st.Online {
		t.Errorf("status offline, want online")
	}

	// Peer hangup takes the port offline.
	peer.Close()
	deadline := time.Now().Add(2 * time.Second)
	for p.Status().Online {
		if time.Now().After(deadline) {
			t.Fatal("port still online after peer close")
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func TestServerReplaceKicksOldConnection(t *testing.T) {
	sw, cap := newSwitchWithCapture(t)
	path := filepath.Join(t.TempDir(), "port.sock")

	p, err := NewServer(sw, ServerConfig{
		ID: "s1", Transport: "unix", Listen: path, Mode: ModeReplace,
		Attrs: switchcore.PortAttrs{VLAN: switchcore.VLANTrunk},
	})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	if err := sw.AddPort(p, switchcore.PortAttrs{VLAN: switchcore.VLANTrunk}); err != nil {
		t.Fatal(err)
	}

	c1, err := net.Dial("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	writeStreamFrame(t, c1, testFrame(1))
	cap.waitFrames(t, 1)

	// Second client replaces the first: c1 sees EOF.
	c2, err := net.Dial("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	defer c2.Close()
	c1.SetReadDeadline(time.Now().Add(2 * time.Second))
	one := make([]byte, 1)
	if _, err := c1.Read(one); err == nil {
		t.Errorf("old connection still alive after replace")
	}

	writeStreamFrame(t, c2, testFrame(2))
	got := cap.waitFrames(t, 2)
	if got[1][14] != 2 {
		t.Errorf("frame 2 payload = %d", got[1][14])
	}
}

func TestServerOccupyRejectsNewConnection(t *testing.T) {
	sw, _ := newSwitchWithCapture(t)
	path := filepath.Join(t.TempDir(), "port.sock")

	p, err := NewServer(sw, ServerConfig{
		ID: "s1", Transport: "unix", Listen: path, Mode: ModeOccupy,
		Attrs: switchcore.PortAttrs{VLAN: switchcore.VLANTrunk},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := sw.AddPort(p, switchcore.PortAttrs{VLAN: switchcore.VLANTrunk}); err != nil {
		t.Fatal(err)
	}

	c1, err := net.Dial("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	defer c1.Close()
	writeStreamFrame(t, c1, testFrame(1)) // ensures c1 is adopted

	deadline := time.Now().Add(2 * time.Second)
	for !p.Status().Online {
		if time.Now().After(deadline) {
			t.Fatal("server never adopted c1")
		}
		time.Sleep(5 * time.Millisecond)
	}

	c2, err := net.Dial("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	defer c2.Close()
	c2.SetReadDeadline(time.Now().Add(2 * time.Second))
	one := make([]byte, 1)
	if _, err := c2.Read(one); err == nil {
		t.Errorf("second connection not rejected in occupy mode")
	}

	// c1 still works.
	writeStreamFrame(t, c1, testFrame(3))
	if !p.Status().Online {
		t.Errorf("c1 dropped, want still online")
	}
}

func TestServerMultiplexSubports(t *testing.T) {
	sw, cap := newSwitchWithCapture(t)
	path := filepath.Join(t.TempDir(), "port.sock")

	p, err := NewServer(sw, ServerConfig{
		ID: "mx", Transport: "unix", Listen: path, Mode: ModeMultiplex,
		Attrs: switchcore.PortAttrs{VLAN: switchcore.VLANTrunk},
	})
	if err != nil {
		t.Fatal(err)
	}
	// The parent multiplex port itself carries no traffic but is tracked
	// by the manager; subports register themselves.

	c1, _ := net.Dial("unix", path)
	defer c1.Close()
	c2, _ := net.Dial("unix", path)
	defer c2.Close()

	writeStreamFrame(t, c1, testFrame(1))
	writeStreamFrame(t, c2, testFrame(2))
	cap.waitFrames(t, 2)

	deadline := time.Now().Add(2 * time.Second)
	var st Status
	for {
		st = p.Status()
		if len(st.Connections) == 2 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("connections = %v, want 2 subports", st.Connections)
		}
		time.Sleep(5 * time.Millisecond)
	}
	// Unix clients are unbound: anonymous IDs, smallest first.
	want := []string{"mx@anonymous-0", "mx@anonymous-1"}
	if st.Connections[0] != want[0] || st.Connections[1] != want[1] {
		t.Errorf("connections = %v, want %v", st.Connections, want)
	}

	// Flood from capture must reach both subports. c1 first drains the
	// flooded copy of c2's earlier frame (subports flood to each other).
	sw.Deliver("cap", testFrame(9))
	f1 := readStreamFrame(t, c1)
	if f1[14] == 2 {
		f1 = readStreamFrame(t, c1)
	}
	f2 := readStreamFrame(t, c2)
	if f2[14] == 1 {
		f2 = readStreamFrame(t, c2)
	}
	if f1[14] != 9 || f2[14] != 9 {
		t.Errorf("flood payloads = %d,%d want 9,9", f1[14], f2[14])
	}

	// Closing c1 frees anonymous-0 for the next client.
	c1.Close()
	deadline = time.Now().Add(2 * time.Second)
	for len(p.Status().Connections) != 1 {
		if time.Now().After(deadline) {
			t.Fatal("subport not removed after close")
		}
		time.Sleep(5 * time.Millisecond)
	}
	c3, _ := net.Dial("unix", path)
	defer c3.Close()
	writeStreamFrame(t, c3, testFrame(3))
	deadline = time.Now().Add(2 * time.Second)
	for {
		st = p.Status()
		if len(st.Connections) == 2 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("connections = %v, want 2", st.Connections)
		}
		time.Sleep(5 * time.Millisecond)
	}
	if st.Connections[0] != "mx@anonymous-0" {
		t.Errorf("freed anonymous ID not reused: %v", st.Connections)
	}
}

func TestDgramServerPeerSemantics(t *testing.T) {
	for _, mode := range []ReplacingMode{ModeReplace, ModeOccupy} {
		t.Run(string(mode), func(t *testing.T) {
			sw, cap := newSwitchWithCapture(t)

			p, err := NewServer(sw, ServerConfig{
				ID: "d1", Transport: "udp", Listen: "127.0.0.1:0", Mode: mode,
				Attrs: switchcore.PortAttrs{VLAN: switchcore.VLANTrunk},
			})
			if err != nil {
				t.Fatal(err)
			}
			if err := sw.AddPort(p, switchcore.PortAttrs{VLAN: switchcore.VLANTrunk}); err != nil {
				t.Fatal(err)
			}
			addr := p.(*dgramServer).pc.LocalAddr().String()

			c1, _ := net.Dial("udp", addr)
			defer c1.Close()
			c2, _ := net.Dial("udp", addr)
			defer c2.Close()

			c1.Write(testFrame(1))
			cap.waitFrames(t, 1)
			if mode == ModeReplace {
				// c2 takes over as peer.
				c2.Write(testFrame(2))
				cap.waitFrames(t, 2)
			} else {
				// occupy: c2's datagram is dropped, c1 stays peer.
				c2.Write(testFrame(2))
				c1.Write(testFrame(3))
				cap.waitFrames(t, 2)
			}

			// Reply goes to the current peer.
			sw.Deliver("cap", testFrame(9))
			c1.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
			c2.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
			buf := make([]byte, 2048)

			if mode == ModeReplace {
				if n, err := c2.Read(buf); err != nil || buf[14] != 9 || n != 60 {
					t.Errorf("replace: c2 read n=%d err=%v", n, err)
				}
			} else {
				if n, err := c1.Read(buf); err != nil || buf[14] != 9 || n != 60 {
					t.Errorf("occupy: c1 read n=%d err=%v", n, err)
				}
			}
		})
	}
}

func TestDgramOccupyDropsOtherSenders(t *testing.T) {
	sw, cap := newSwitchWithCapture(t)
	p, err := NewServer(sw, ServerConfig{
		ID: "d1", Transport: "udp", Listen: "127.0.0.1:0", Mode: ModeOccupy,
		Attrs: switchcore.PortAttrs{VLAN: switchcore.VLANTrunk},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := sw.AddPort(p, switchcore.PortAttrs{VLAN: switchcore.VLANTrunk}); err != nil {
		t.Fatal(err)
	}
	addr := p.(*dgramServer).pc.LocalAddr().String()

	c1, _ := net.Dial("udp", addr)
	defer c1.Close()
	c2, _ := net.Dial("udp", addr)
	defer c2.Close()

	c1.Write(testFrame(1))
	cap.waitFrames(t, 1)
	c2.Write(testFrame(2)) // must be dropped
	c1.Write(testFrame(3))
	got := cap.waitFrames(t, 2)
	if got[1][14] != 3 {
		t.Errorf("second delivered frame = %d, want 3 (frame from c2 must be dropped)", got[1][14])
	}
}

func TestFramingRejectsOversizeAndZero(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	sio := newStreamIO(b)

	go func() {
		hdr := make([]byte, 4)
		binary.BigEndian.PutUint32(hdr, maxFrameSize+1)
		a.Write(hdr)
	}()
	if _, err := sio.ReadFrame(); err == nil {
		t.Errorf("oversize frame accepted")
	}

	a2, b2 := net.Pipe()
	defer a2.Close()
	defer b2.Close()
	sio2 := newStreamIO(b2)
	go a2.Write(make([]byte, 4)) // zero length
	if _, err := sio2.ReadFrame(); err == nil {
		t.Errorf("zero-length frame accepted")
	}
}

func TestFramingRoundtrip(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	w := newStreamIO(a)
	r := newStreamIO(b)

	want := testFrame(0x42)
	go w.WriteFrame(want)
	got, err := r.ReadFrame()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("roundtrip mismatch")
	}
}
