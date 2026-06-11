package api

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"
)

// ParseListen maps a control-socket listen string to (network, address):
// "ip:port" = tcp4, "[ip]:port" = tcp6, anything else = unix socket path.
func ParseListen(s string) (network, addr string) {
	host, _, err := net.SplitHostPort(s)
	if err != nil {
		return "unix", s
	}
	if strings.HasPrefix(s, "[") || strings.Contains(host, ":") {
		return "tcp6", s
	}
	return "tcp4", s
}

// Server is the REST control plane.
type Server struct {
	http net.Listener
	srv  *http.Server
}

// Backend is what the handlers need; *manager.Manager implements it.
type Backend interface {
	CreatePort(req PortRequest) (PortInfo, error)
	GetPort(id string) (PortInfo, error)
	ListPorts() []PortInfo
	PatchPort(id string, patch PortPatch) (PortInfo, error)
	DeletePort(id string) error

	FDB() []FDBRow
	DeleteFDBEntry(vlan int, mac string) error
	FlushFDB(req FDBFlushRequest) int
	PutStaticFDB(req StaticFDBRequest) error
	DeleteStaticFDB(vlan int, mac string) error
	GetFDBConfig() FDBConfig
	SetFDBConfig(cfg FDBConfig) error

	SetSTP(req STPRequest) error
	GetSTP() STPResponse

	GatewayBackend
}

// Listen starts serving the API on the given listen string. authToken, when
// non-empty, requires `Authorization: Bearer <token>` on every request.
func Listen(listen, authToken string, b Backend) (*Server, error) {
	network, addr := ParseListen(listen)
	if network == "unix" {
		if fi, err := os.Stat(addr); err == nil && fi.Mode()&os.ModeSocket != 0 {
			os.Remove(addr)
		}
	}
	ln, err := net.Listen(network, addr)
	if err != nil {
		return nil, fmt.Errorf("control socket %s %s: %w", network, addr, err)
	}

	srv := &http.Server{Handler: WithAuth(authToken, NewHandler(b))}
	go srv.Serve(ln)
	return &Server{http: ln, srv: srv}, nil
}

// WithAuth enforces a bearer token on every request; an empty token
// disables authentication (e.g. unix sockets guarded by file permissions).
func WithAuth(token string, next http.Handler) http.Handler {
	if token == "" {
		return next
	}
	want := []byte("Bearer " + token)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got := []byte(r.Header.Get("Authorization"))
		// Length-equalize before the constant-time compare so length
		// itself doesn't short-circuit.
		ok := len(got) == len(want) && subtle.ConstantTimeCompare(got, want) == 1
		if !ok {
			w.Header().Set("WWW-Authenticate", "Bearer")
			writeErr(w, http.StatusUnauthorized, fmt.Errorf("unauthorized"))
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Server) Addr() net.Addr { return s.http.Addr() }

func (s *Server) Close() error {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	return s.srv.Shutdown(ctx)
}

// NewHandler builds the route table (exported for tests).
func NewHandler(b Backend) http.Handler {
	h := &handlers{b: b}
	mux := http.NewServeMux()

	mux.HandleFunc("POST /api/v1/ports", h.createPort)
	mux.HandleFunc("GET /api/v1/ports", h.listPorts)
	mux.HandleFunc("GET /api/v1/ports/{id}", h.getPort)
	mux.HandleFunc("PATCH /api/v1/ports/{id}", h.patchPort)
	mux.HandleFunc("DELETE /api/v1/ports/{id}", h.deletePort)
	mux.HandleFunc("GET /api/v1/fdb", h.fdb)
	mux.HandleFunc("DELETE /api/v1/fdb/{vlan}/{mac}", h.deleteFDBEntry)
	mux.HandleFunc("POST /api/v1/fdb/flush", h.flushFDB)
	mux.HandleFunc("GET /api/v1/fdb/static", h.listStaticFDB)
	mux.HandleFunc("PUT /api/v1/fdb/static", h.putStaticFDB)
	mux.HandleFunc("DELETE /api/v1/fdb/static/{vlan}/{mac}", h.deleteStaticFDB)
	mux.HandleFunc("GET /api/v1/fdb/config", h.getFDBConfig)
	mux.HandleFunc("PUT /api/v1/fdb/config", h.setFDBConfig)
	mux.HandleFunc("GET /api/v1/stp", h.getSTP)
	mux.HandleFunc("PUT /api/v1/stp", h.setSTP)

	registerGatewayRoutes(mux, h)
	return mux
}

type handlers struct {
	b Backend
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, code int, err error) {
	writeJSON(w, code, Error{Error: err.Error()})
}

// errCode maps backend errors to HTTP status codes by message shape.
func errCode(err error) int {
	msg := err.Error()
	switch {
	case strings.Contains(msg, "not found"):
		return http.StatusNotFound
	case strings.Contains(msg, "already exists"):
		return http.StatusConflict
	default:
		return http.StatusBadRequest
	}
}

func decodeBody(w http.ResponseWriter, r *http.Request, v any) bool {
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		writeErr(w, http.StatusBadRequest, fmt.Errorf("bad request body: %w", err))
		return false
	}
	return true
}

func (h *handlers) createPort(w http.ResponseWriter, r *http.Request) {
	var req PortRequest
	if !decodeBody(w, r, &req) {
		return
	}
	info, err := h.b.CreatePort(req)
	if err != nil {
		writeErr(w, errCode(err), err)
		return
	}
	writeJSON(w, http.StatusCreated, info)
}

func (h *handlers) listPorts(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, h.b.ListPorts())
}

func (h *handlers) getPort(w http.ResponseWriter, r *http.Request) {
	info, err := h.b.GetPort(r.PathValue("id"))
	if err != nil {
		writeErr(w, errCode(err), err)
		return
	}
	writeJSON(w, http.StatusOK, info)
}

func (h *handlers) patchPort(w http.ResponseWriter, r *http.Request) {
	var patch PortPatch
	if !decodeBody(w, r, &patch) {
		return
	}
	info, err := h.b.PatchPort(r.PathValue("id"), patch)
	if err != nil {
		writeErr(w, errCode(err), err)
		return
	}
	writeJSON(w, http.StatusOK, info)
}

func (h *handlers) deletePort(w http.ResponseWriter, r *http.Request) {
	if err := h.b.DeletePort(r.PathValue("id")); err != nil {
		writeErr(w, errCode(err), err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// parseVLANSelector parses a vlan path/query value: 0 = untagged domain,
// 1-4094 = that VLAN.
func parseVLANSelector(s string) (int, error) {
	v, err := strconv.Atoi(s)
	if err != nil || v < 0 || v > 4094 {
		return 0, fmt.Errorf("bad vlan %q (0 = untagged domain, 1-4094)", s)
	}
	return v, nil
}

func (h *handlers) fdb(w http.ResponseWriter, r *http.Request) {
	rows := h.b.FDB()
	q := r.URL.Query()
	filtered := make([]FDBRow, 0, len(rows))
	vlanFilter := -1
	if s := q.Get("vlan"); s != "" {
		v, err := parseVLANSelector(s)
		if err != nil {
			writeErr(w, http.StatusBadRequest, err)
			return
		}
		vlanFilter = v
	}
	port, mac := q.Get("port"), strings.ToLower(q.Get("mac"))
	for _, row := range rows {
		if vlanFilter >= 0 && row.VLAN != vlanFilter {
			continue
		}
		if port != "" && row.Port != port {
			continue
		}
		if mac != "" && row.MAC != mac {
			continue
		}
		filtered = append(filtered, row)
	}
	writeJSON(w, http.StatusOK, filtered)
}

func (h *handlers) deleteFDBEntry(w http.ResponseWriter, r *http.Request) {
	vlan, err := parseVLANSelector(r.PathValue("vlan"))
	if err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	if err := h.b.DeleteFDBEntry(vlan, r.PathValue("mac")); err != nil {
		writeErr(w, errCode(err), err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *handlers) flushFDB(w http.ResponseWriter, r *http.Request) {
	var req FDBFlushRequest
	if !decodeBody(w, r, &req) {
		return
	}
	n := h.b.FlushFDB(req)
	writeJSON(w, http.StatusOK, map[string]int{"flushed": n})
}

func (h *handlers) listStaticFDB(w http.ResponseWriter, r *http.Request) {
	rows := h.b.FDB()
	out := make([]FDBRow, 0)
	for _, row := range rows {
		if row.Static {
			out = append(out, row)
		}
	}
	writeJSON(w, http.StatusOK, out)
}

func (h *handlers) putStaticFDB(w http.ResponseWriter, r *http.Request) {
	var req StaticFDBRequest
	if !decodeBody(w, r, &req) {
		return
	}
	if err := h.b.PutStaticFDB(req); err != nil {
		writeErr(w, errCode(err), err)
		return
	}
	writeJSON(w, http.StatusOK, req)
}

func (h *handlers) deleteStaticFDB(w http.ResponseWriter, r *http.Request) {
	vlan, err := parseVLANSelector(r.PathValue("vlan"))
	if err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	if err := h.b.DeleteStaticFDB(vlan, r.PathValue("mac")); err != nil {
		writeErr(w, errCode(err), err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *handlers) getSTP(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, h.b.GetSTP())
}

func (h *handlers) setSTP(w http.ResponseWriter, r *http.Request) {
	var req STPRequest
	if !decodeBody(w, r, &req) {
		return
	}
	if err := h.b.SetSTP(req); err != nil {
		writeErr(w, errCode(err), err)
		return
	}
	writeJSON(w, http.StatusOK, h.b.GetSTP())
}

func (h *handlers) getFDBConfig(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, h.b.GetFDBConfig())
}

func (h *handlers) setFDBConfig(w http.ResponseWriter, r *http.Request) {
	var cfg FDBConfig
	if !decodeBody(w, r, &cfg) {
		return
	}
	if err := h.b.SetFDBConfig(cfg); err != nil {
		writeErr(w, errCode(err), err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
