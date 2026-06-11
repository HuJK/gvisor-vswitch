package manager_test

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/HuJK/gvisor-vswitch/internal/api"
	"github.com/HuJK/gvisor-vswitch/internal/manager"
)

func newAPI(t *testing.T) (*httptest.Server, *manager.Manager) {
	t.Helper()
	m := manager.New()
	t.Cleanup(m.Close)
	srv := httptest.NewServer(api.NewHandler(m))
	t.Cleanup(srv.Close)
	return srv, m
}

func doJSON(t *testing.T, method, url string, body any) (*http.Response, []byte) {
	t.Helper()
	var rd *bytes.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
		rd = bytes.NewReader(b)
	} else {
		rd = bytes.NewReader(nil)
	}
	req, err := http.NewRequest(method, url, rd)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var buf bytes.Buffer
	buf.ReadFrom(resp.Body)
	return resp, buf.Bytes()
}

func TestPortLifecycleViaAPI(t *testing.T) {
	srv, _ := newAPI(t)
	sock := filepath.Join(t.TempDir(), "vm1.sock")

	// Create a unix server port.
	vlan := 100
	resp, body := doJSON(t, "POST", srv.URL+"/api/v1/ports", api.PortRequest{
		Identifier: "vm1",
		VLAN:       &vlan,
		Mode:       "server",
		Transport:  "unix",
		Local:      sock,
	})
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("create: %d %s", resp.StatusCode, body)
	}

	// Duplicate identifier conflicts.
	resp, _ = doJSON(t, "POST", srv.URL+"/api/v1/ports", api.PortRequest{
		Identifier: "vm1", Mode: "server", Transport: "tcp", Local: "127.0.0.1:0",
	})
	if resp.StatusCode != http.StatusConflict {
		t.Errorf("duplicate create: %d, want 409", resp.StatusCode)
	}

	// A VM connects -> port online.
	conn, err := net.Dial("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	deadline := time.Now().Add(2 * time.Second)
	for {
		resp, body = doJSON(t, "GET", srv.URL+"/api/v1/ports/vm1", nil)
		var info api.PortInfo
		json.Unmarshal(body, &info)
		if info.Online {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("port never online: %s", body)
		}
		time.Sleep(10 * time.Millisecond)
	}

	// PATCH: vlan 4095 = trunk, port_security on.
	patch := map[string]any{"vlan": 4095, "port_security": "02:00:00:00:00:01"}
	resp, body = doJSON(t, "PATCH", srv.URL+"/api/v1/ports/vm1", patch)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("patch: %d %s", resp.StatusCode, body)
	}
	var info api.PortInfo
	json.Unmarshal(body, &info)
	if info.VLAN != 4095 || info.PortSecurity == nil || *info.PortSecurity != "02:00:00:00:00:01" {
		t.Errorf("patched info = %s", body)
	}

	// List.
	resp, body = doJSON(t, "GET", srv.URL+"/api/v1/ports", nil)
	var list []api.PortInfo
	json.Unmarshal(body, &list)
	if len(list) != 1 {
		t.Errorf("list = %s", body)
	}

	// Delete; the connected client sees EOF.
	resp, _ = doJSON(t, "DELETE", srv.URL+"/api/v1/ports/vm1", nil)
	if resp.StatusCode != http.StatusNoContent {
		t.Errorf("delete: %d", resp.StatusCode)
	}
	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	one := make([]byte, 1)
	if _, err := conn.Read(one); err == nil {
		t.Errorf("connection survived port deletion")
	}
	resp, _ = doJSON(t, "GET", srv.URL+"/api/v1/ports/vm1", nil)
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("get after delete: %d, want 404", resp.StatusCode)
	}
}

func TestFDBEndpoint(t *testing.T) {
	srv, m := newAPI(t)
	sock := filepath.Join(t.TempDir(), "vm.sock")

	vlan := 7
	resp, body := doJSON(t, "POST", srv.URL+"/api/v1/ports", api.PortRequest{
		Identifier: "vm", VLAN: &vlan, Mode: "server", Transport: "unix", Local: sock,
	})
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("create: %d %s", resp.StatusCode, body)
	}

	conn, err := net.Dial("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	// Send one frame so a MAC is learned.
	frame := make([]byte, 60)
	copy(frame[0:6], []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff})
	copy(frame[6:12], []byte{0x02, 0xaa, 0, 0, 0, 1})
	frame[12], frame[13] = 0x08, 0x00
	hdr := []byte{0, 0, 0, 60}
	if _, err := conn.Write(append(hdr, frame...)); err != nil {
		t.Fatal(err)
	}

	deadline := time.Now().Add(2 * time.Second)
	for {
		if rows := m.FDB(); len(rows) == 1 {
			if rows[0].MAC != "02:aa:00:00:00:01" || rows[0].Port != "vm" || rows[0].VLAN != 7 {
				t.Fatalf("fdb row = %+v", rows[0])
			}
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("fdb never learned the MAC")
		}
		time.Sleep(10 * time.Millisecond)
	}

	resp, body = doJSON(t, "GET", srv.URL+"/api/v1/fdb", nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("fdb: %d", resp.StatusCode)
	}
	var rows []api.FDBRow
	json.Unmarshal(body, &rows)
	if len(rows) != 1 {
		t.Errorf("fdb rows = %s", body)
	}
}

func TestParseListen(t *testing.T) {
	cases := []struct{ in, network string }{
		{"127.0.0.1:8080", "tcp4"},
		{"[::1]:8080", "tcp6"},
		{"/run/gvswitch.sock", "unix"},
		{"relative.sock", "unix"},
	}
	for _, c := range cases {
		if n, _ := api.ParseListen(c.in); n != c.network {
			t.Errorf("ParseListen(%q) network = %q, want %q", c.in, n, c.network)
		}
	}
}

var _ = fmt.Sprintf // keep fmt for debug edits

func TestAuthMiddleware(t *testing.T) {
	m := manager.New()
	t.Cleanup(m.Close)
	srv := httptest.NewServer(api.WithAuth("sekret", api.NewHandler(m)))
	t.Cleanup(srv.Close)

	// No token -> 401.
	resp, body := doJSON(t, "GET", srv.URL+"/api/v1/ports", nil)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("no token: %d %s, want 401", resp.StatusCode, body)
	}

	// Wrong token -> 401.
	req, _ := http.NewRequest("GET", srv.URL+"/api/v1/ports", nil)
	req.Header.Set("Authorization", "Bearer nope")
	r2, _ := http.DefaultClient.Do(req)
	r2.Body.Close()
	if r2.StatusCode != http.StatusUnauthorized {
		t.Fatalf("wrong token: %d, want 401", r2.StatusCode)
	}

	// Correct token -> 200.
	req, _ = http.NewRequest("GET", srv.URL+"/api/v1/ports", nil)
	req.Header.Set("Authorization", "Bearer sekret")
	r3, _ := http.DefaultClient.Do(req)
	r3.Body.Close()
	if r3.StatusCode != http.StatusOK {
		t.Fatalf("good token: %d, want 200", r3.StatusCode)
	}

	// Empty token disables auth.
	srv2 := httptest.NewServer(api.WithAuth("", api.NewHandler(m)))
	t.Cleanup(srv2.Close)
	resp, _ = doJSON(t, "GET", srv2.URL+"/api/v1/ports", nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("no auth configured: %d, want 200", resp.StatusCode)
	}
}

func TestFDBManagementAPI(t *testing.T) {
	srv, m := newAPI(t)
	_ = m

	// Static entry on vlan 7.
	resp, body := doJSON(t, "PUT", srv.URL+"/api/v1/fdb/static", api.StaticFDBRequest{
		VLAN: 7, MAC: "02:aa:00:00:00:02", Port: "vmX",
	})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("put static: %d %s", resp.StatusCode, body)
	}
	// And one on the untagged domain (vlan 0).
	resp, body = doJSON(t, "PUT", srv.URL+"/api/v1/fdb/static", api.StaticFDBRequest{
		VLAN: 0, MAC: "02:aa:00:00:00:03", Port: "vmY",
	})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("put static untagged: %d %s", resp.StatusCode, body)
	}

	resp, body = doJSON(t, "GET", srv.URL+"/api/v1/fdb/static", nil)
	var rows []api.FDBRow
	json.Unmarshal(body, &rows)
	if len(rows) != 2 {
		t.Fatalf("static list = %s", body)
	}

	// Filtered FDB query.
	resp, body = doJSON(t, "GET", srv.URL+"/api/v1/fdb?vlan=7", nil)
	rows = nil
	json.Unmarshal(body, &rows)
	if len(rows) != 1 || !rows[0].Static || rows[0].Port != "vmX" {
		t.Fatalf("vlan filter = %s", body)
	}
	resp, body = doJSON(t, "GET", srv.URL+"/api/v1/fdb?vlan=0", nil)
	rows = nil
	json.Unmarshal(body, &rows)
	if len(rows) != 1 || rows[0].Port != "vmY" {
		t.Fatalf("untagged (vlan 0) filter = %s", body)
	}

	// Dynamic delete refuses static entries.
	resp, body = doJSON(t, "DELETE", srv.URL+"/api/v1/fdb/7/02:aa:00:00:00:02", nil)
	if resp.StatusCode == http.StatusNoContent {
		t.Fatal("dynamic delete removed a static entry")
	}

	// Static delete.
	resp, _ = doJSON(t, "DELETE", srv.URL+"/api/v1/fdb/static/7/02:aa:00:00:00:02", nil)
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("delete static: %d", resp.StatusCode)
	}
	resp, _ = doJSON(t, "DELETE", srv.URL+"/api/v1/fdb/static/0/02:aa:00:00:00:03", nil)
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("delete static untagged: %d", resp.StatusCode)
	}

	// Flush + config.
	resp, body = doJSON(t, "POST", srv.URL+"/api/v1/fdb/flush", api.FDBFlushRequest{})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("flush: %d %s", resp.StatusCode, body)
	}
	resp, _ = doJSON(t, "PUT", srv.URL+"/api/v1/fdb/config", api.FDBConfig{AgingSeconds: 120})
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("set config: %d", resp.StatusCode)
	}
	resp, body = doJSON(t, "GET", srv.URL+"/api/v1/fdb/config", nil)
	var cfg api.FDBConfig
	json.Unmarshal(body, &cfg)
	if cfg.AgingSeconds != 120 {
		t.Fatalf("config = %s", body)
	}
	resp, _ = doJSON(t, "PUT", srv.URL+"/api/v1/fdb/config", api.FDBConfig{AgingSeconds: 0})
	if resp.StatusCode == http.StatusNoContent {
		t.Fatal("zero aging accepted")
	}
}

func TestPortEnableDisableAndStats(t *testing.T) {
	srv, _ := newAPI(t)
	sock := filepath.Join(t.TempDir(), "vm.sock")

	vlan := 5
	resp, body := doJSON(t, "POST", srv.URL+"/api/v1/ports", api.PortRequest{
		Identifier: "vm", VLAN: &vlan, Mode: "server", Transport: "unix", Local: sock,
	})
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("create: %d %s", resp.StatusCode, body)
	}
	var info api.PortInfo
	json.Unmarshal(body, &info)
	if !info.Enabled {
		t.Errorf("new port not enabled by default")
	}

	// Disable, then re-enable via PATCH.
	resp, body = doJSON(t, "PATCH", srv.URL+"/api/v1/ports/vm", map[string]any{"enabled": false})
	json.Unmarshal(body, &info)
	if resp.StatusCode != http.StatusOK || info.Enabled {
		t.Fatalf("disable: %d %s", resp.StatusCode, body)
	}
	resp, body = doJSON(t, "PATCH", srv.URL+"/api/v1/ports/vm", map[string]any{"enabled": true})
	json.Unmarshal(body, &info)
	if !info.Enabled {
		t.Fatalf("re-enable: %s", body)
	}

	// Stats counted after a frame.
	conn, err := net.Dial("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	frame := make([]byte, 60)
	copy(frame[0:6], []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff})
	copy(frame[6:12], []byte{0x02, 0xaa, 0, 0, 0, 9})
	frame[12], frame[13] = 0x08, 0x00
	conn.Write(append([]byte{0, 0, 0, 60}, frame...))

	deadline := time.Now().Add(2 * time.Second)
	for {
		_, body = doJSON(t, "GET", srv.URL+"/api/v1/ports/vm", nil)
		json.Unmarshal(body, &info)
		if info.Stats.RxFrames >= 1 && info.Stats.RxBytes >= 60 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("stats never counted: %s", body)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestAutoRemoveOnPeerClose(t *testing.T) {
	srv, _ := newAPI(t)
	dir := t.TempDir()

	// Default: peer closing the connection removes the port.
	vlan := 5
	sockA := filepath.Join(dir, "a.sock")
	resp, body := doJSON(t, "POST", srv.URL+"/api/v1/ports", api.PortRequest{
		Identifier: "vmA", VLAN: &vlan, Mode: "server", Transport: "unix", Local: sockA,
	})
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("create: %d %s", resp.StatusCode, body)
	}
	var info api.PortInfo
	json.Unmarshal(body, &info)
	if !info.AutoRemove {
		t.Fatalf("auto_remove default = false, want true: %s", body)
	}

	conn, err := net.Dial("unix", sockA)
	if err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(2 * time.Second)
	for {
		_, body = doJSON(t, "GET", srv.URL+"/api/v1/ports/vmA", nil)
		json.Unmarshal(body, &info)
		if info.Online {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("never online")
		}
		time.Sleep(10 * time.Millisecond)
	}
	conn.Close()

	deadline = time.Now().Add(3 * time.Second)
	for {
		resp, _ = doJSON(t, "GET", srv.URL+"/api/v1/ports/vmA", nil)
		if resp.StatusCode == http.StatusNotFound {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("port not auto-removed after peer close")
		}
		time.Sleep(10 * time.Millisecond)
	}
	// The listening socket is gone too.
	if _, err := net.Dial("unix", sockA); err == nil {
		t.Fatal("listener still accepting after auto-remove")
	}

	// Opt-out: auto_remove=false keeps the port (offline) for reconnect.
	keep := false
	sockB := filepath.Join(dir, "b.sock")
	resp, body = doJSON(t, "POST", srv.URL+"/api/v1/ports", api.PortRequest{
		Identifier: "vmB", VLAN: &vlan, Mode: "server", Transport: "unix", Local: sockB,
		AutoRemove: &keep,
	})
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("create vmB: %d %s", resp.StatusCode, body)
	}
	conn2, err := net.Dial("unix", sockB)
	if err != nil {
		t.Fatal(err)
	}
	deadline = time.Now().Add(2 * time.Second)
	for {
		_, body = doJSON(t, "GET", srv.URL+"/api/v1/ports/vmB", nil)
		json.Unmarshal(body, &info)
		if info.Online {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("vmB never online")
		}
		time.Sleep(10 * time.Millisecond)
	}
	conn2.Close()

	time.Sleep(300 * time.Millisecond) // would have been removed by now
	resp, body = doJSON(t, "GET", srv.URL+"/api/v1/ports/vmB", nil)
	json.Unmarshal(body, &info)
	if resp.StatusCode != http.StatusOK || info.Online {
		t.Fatalf("vmB: %d online=%v, want kept offline", resp.StatusCode, info.Online)
	}
	// And it accepts a reconnect.
	conn3, err := net.Dial("unix", sockB)
	if err != nil {
		t.Fatalf("reconnect: %v", err)
	}
	conn3.Close()
}
