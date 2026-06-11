package gateway

import (
	"fmt"
	"net"
	"sort"

	sns "github.com/cloudflare/slirpnetstack"
)

// ForwardRec describes one installed port forward.
type ForwardRec struct {
	ID      string
	Type    string // local | remote
	Network string // tcp | udp
	Bind    string
	Host    string
}

type forwardRec struct {
	ForwardRec
	listener sns.Listener // local forwards
	key      string       // remote forwards: DynFwdTable key
}

// AddForward installs a forward rule at runtime.
//   - local:  listen on the host at bind, proxy connections to host (a guest
//     address) through the netstack
//   - remote: guest connections to bind (gateway-side ip:port) are proxied
//     to host (a host-side address)
func (g *Gateway) AddForward(typ, network, bind, host string) (ForwardRec, error) {
	bindH, bindP, err := net.SplitHostPort(bind)
	if err != nil {
		return ForwardRec{}, fmt.Errorf("bad bind %q: %w", bind, err)
	}
	hostH, hostP, err := net.SplitHostPort(host)
	if err != nil {
		return ForwardRec{}, fmt.Errorf("bad host %q: %w", host, err)
	}
	rf, err := sns.NewFwdAddr(network, bindH, bindP, hostH, hostP)
	if err != nil {
		return ForwardRec{}, err
	}

	rec := &forwardRec{ForwardRec: ForwardRec{
		Type:    typ,
		Network: network,
		Bind:    bind,
		Host:    host,
	}}

	switch typ {
	case "local":
		// The proxy's first netstack write needs the guest's link
		// address; prime ARP like slirpnetstack does at startup.
		if ip := net.ParseIP(hostH); ip != nil && ip.To4() != nil {
			sns.StackPrimeArp(g.stk, nicID, ip)
		}
		var ln sns.Listener
		switch network {
		case "tcp":
			ln, err = sns.DynLocalForwardTCP(g.state, g.stk, rf)
		case "udp":
			ln, err = sns.DynLocalForwardUDP(g.state, g.stk, rf)
		default:
			err = fmt.Errorf("network must be tcp or udp, got %q", network)
		}
		if err != nil {
			return ForwardRec{}, err
		}
		rec.listener = ln
	case "remote":
		key, err := g.fwdTable.Add(rf)
		if err != nil {
			return ForwardRec{}, err
		}
		rec.key = key
	default:
		return ForwardRec{}, fmt.Errorf("type must be local or remote, got %q", typ)
	}

	g.fwdMu.Lock()
	g.fwdSeq++
	rec.ID = fmt.Sprintf("fwd-%d", g.fwdSeq)
	g.forwards[rec.ID] = rec
	g.fwdMu.Unlock()
	return rec.ForwardRec, nil
}

// DeleteForward removes a forward rule.
func (g *Gateway) DeleteForward(id string) error {
	g.fwdMu.Lock()
	rec, ok := g.forwards[id]
	if ok {
		delete(g.forwards, id)
	}
	g.fwdMu.Unlock()
	if !ok {
		return fmt.Errorf("forward %q not found", id)
	}
	switch rec.Type {
	case "local":
		rec.listener.Close()
	case "remote":
		g.fwdTable.Remove(rec.Network, rec.key)
	}
	return nil
}

// ForwardSpec is the identity of a forward rule for declarative updates.
type ForwardSpec struct {
	Type    string
	Network string
	Bind    string
	Host    string
}

func (s ForwardSpec) key() string {
	return s.Type + "|" + s.Network + "|" + s.Bind + "|" + s.Host
}

// ReplaceForwards reconciles the installed forwards against the desired
// set: rules matching an existing one (textual tuple match) are kept alive
// (their listeners are not recreated and keep their IDs), extra rules are
// removed, missing ones added. Returns the resulting set. On an add
// failure the already-applied changes stay (re-PUT to converge); the error
// names the failing rule.
func (g *Gateway) ReplaceForwards(desired []ForwardSpec) ([]ForwardRec, error) {
	want := make(map[string]ForwardSpec, len(desired))
	for _, d := range desired {
		if _, dup := want[d.key()]; dup {
			return nil, fmt.Errorf("duplicate forward %s %s %s -> %s", d.Type, d.Network, d.Bind, d.Host)
		}
		want[d.key()] = d
	}

	// Pass 1: drop rules not in the desired set; note which are kept.
	g.fwdMu.Lock()
	var toDelete []string
	have := make(map[string]bool)
	for id, rec := range g.forwards {
		k := ForwardSpec{rec.Type, rec.Network, rec.Bind, rec.Host}.key()
		if _, keep := want[k]; keep && !have[k] {
			have[k] = true
		} else {
			toDelete = append(toDelete, id)
		}
	}
	g.fwdMu.Unlock()
	for _, id := range toDelete {
		g.DeleteForward(id)
	}

	// Pass 2: add what's missing.
	for k, d := range want {
		if have[k] {
			continue
		}
		if _, err := g.AddForward(d.Type, d.Network, d.Bind, d.Host); err != nil {
			return g.ListForwards(), fmt.Errorf("add %s %s %s -> %s: %w", d.Type, d.Network, d.Bind, d.Host, err)
		}
	}
	return g.ListForwards(), nil
}

// ListForwards snapshots the installed forwards.
func (g *Gateway) ListForwards() []ForwardRec {
	g.fwdMu.Lock()
	defer g.fwdMu.Unlock()
	out := make([]ForwardRec, 0, len(g.forwards))
	for _, rec := range g.forwards {
		out = append(out, rec.ForwardRec)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

func (g *Gateway) closeForwards() {
	g.fwdMu.Lock()
	recs := g.forwards
	g.forwards = make(map[string]*forwardRec)
	g.fwdMu.Unlock()
	for _, rec := range recs {
		if rec.listener != nil {
			rec.listener.Close()
		}
	}
}
