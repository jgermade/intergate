package sshd

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/jgermade/intergate/internal/config"
	"github.com/jgermade/intergate/internal/manage"
	"github.com/jgermade/intergate/internal/store"
	"github.com/jgermade/intergate/internal/wire"
)

// The intergate client's requests to see and change ports, with the
// authority of the key it signed in with: a key that may open a subdomain
// may also manage its ports, within its owner's limits.

// errInternal is what clients see of a failure that is not theirs.
var errInternal = errors.New("internal error, please retry")

// handleWire answers one of the wire requests, or reports false when req
// is not one.
func (c *clientConn) handleWire(req *ssh.Request) bool {
	switch req.Type {
	case wire.InfoRequest, wire.PortAddRequest, wire.PortUpdateRequest, wire.PortDeleteRequest:
	default:
		return false
	}
	if c.srv.Manage == nil {
		req.Reply(false, nil)
		return true
	}
	var reply any
	switch req.Type {
	case wire.InfoRequest:
		reply = c.wireInfo(req.Payload)
	case wire.PortAddRequest:
		reply = c.wirePortAdd(req.Payload)
	case wire.PortUpdateRequest:
		reply = c.wirePortUpdate(req.Payload)
	case wire.PortDeleteRequest:
		reply = c.wirePortDelete(req.Payload)
	}
	req.Reply(true, wire.Marshal(reply))
	return true
}

// failure is the message a client sees for err: its own problems as they
// are, anything else logged and hidden.
func (c *clientConn) failure(what string, err error) string {
	var me *manage.Error
	var ue userError
	switch {
	case errors.As(err, &me):
		return me.Error()
	case errors.As(err, &ue):
		return ue.Error()
	case err.Error() == errInternal.Error(): // already logged by loadGrants
		return err.Error()
	}
	c.log.Error(what, "err", err)
	return errInternal.Error()
}

// userError is a problem with the request, safe to show.
type userError struct{ msg string }

func (e userError) Error() string { return e.msg }

// wireGrant returns the grant and subdomain the key has for name.
func (c *clientConn) wireGrant(ctx context.Context, name string) (store.Grant, *store.Subdomain, error) {
	grants, err := c.loadGrants(ctx)
	if err != nil {
		return store.Grant{}, nil, err
	}
	g, err := pickGrant(grants, name, c.conn.User())
	if err != nil {
		return store.Grant{}, nil, userError{err.Error()}
	}
	d, err := c.srv.store.SubdomainByName(ctx, g.Subdomain)
	if err != nil {
		return store.Grant{}, nil, err
	}
	return g, d, nil
}

func (c *clientConn) actor(g store.Grant) string { return "key " + g.KeyName }

func wireCtx() (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), 10*time.Second)
}

func (c *clientConn) wirePort(p *store.Port) *wire.Port {
	allow := p.Allow
	if allow == nil {
		allow = []string{}
	}
	return &wire.Port{
		Name: p.Name, Protocol: string(p.Protocol), Port: p.Port, Address: c.srv.cfg.PortAddress(string(p.Protocol), p.Port),
		Allow: allow, LocalPort: p.LocalPort, CreatedBy: p.CreatedBy,
	}
}

func (c *clientConn) wireInfo(payload []byte) wire.Info {
	var q wire.InfoQuery
	if len(payload) > 0 {
		if err := json.Unmarshal(payload, &q); err != nil {
			return wire.Info{Reply: wire.Reply{Error: "bad request"}}
		}
	}
	ctx, cancel := wireCtx()
	defer cancel()
	out := wire.Info{Domain: c.srv.cfg.Domain(), Subdomains: []wire.Subdomain{}}
	grants, err := c.loadGrants(ctx)
	if err != nil {
		out.Error = err.Error()
		return out
	}
	found := false
	for _, g := range grants {
		if q.Subdomain != "" && g.Subdomain != q.Subdomain {
			continue
		}
		found = true
		d, err := c.srv.store.SubdomainByName(ctx, g.Subdomain)
		if err != nil {
			out.Error = c.failure("wire info: subdomain", err)
			return out
		}
		list, err := c.srv.store.PortsBySubdomain(ctx, d.ID)
		if err != nil {
			out.Error = c.failure("wire info: ports", err)
			return out
		}
		used, l, err := c.srv.Manage.PortQuota(ctx, d)
		if err != nil {
			out.Error = c.failure("wire info: quota", err)
			return out
		}
		sub := wire.Subdomain{
			Name: d.Name, URL: c.srv.cfg.TunnelURL(d.Name), Ports: []wire.Port{},
			Quota: wire.Quota{Used: used, Max: l.Ports, Ranges: config.FormatPortRanges(l.Ranges)},
		}
		for _, p := range list {
			sub.Ports = append(sub.Ports, *c.wirePort(p))
		}
		out.Subdomains = append(out.Subdomains, sub)
	}
	if q.Subdomain != "" && !found {
		out.Error = "this key is not authorized for " + q.Subdomain
	}
	return out
}

// portByName finds one of d's ports.
func (c *clientConn) portByName(ctx context.Context, d *store.Subdomain, name string) (*store.Port, error) {
	list, err := c.srv.store.PortsBySubdomain(ctx, d.ID)
	if err != nil {
		return nil, err
	}
	for _, p := range list {
		if p.Name == name {
			return p, nil
		}
	}
	return nil, userError{d.Name + " has no port named " + name}
}

func (c *clientConn) wirePortAdd(payload []byte) wire.PortReply {
	var in wire.PortAdd
	if err := json.Unmarshal(payload, &in); err != nil {
		return wire.PortReply{Reply: wire.Reply{Error: "bad request"}}
	}
	allow, ok := wire.ParseAllow(in.Allow)
	if !ok {
		return wire.PortReply{Reply: wire.Reply{Error: "say who may connect to " + in.Name + ": addresses or ranges, or any for anyone"}}
	}
	ctx, cancel := wireCtx()
	defer cancel()
	g, d, err := c.wireGrant(ctx, in.Subdomain)
	if err != nil {
		return wire.PortReply{Reply: wire.Reply{Error: c.failure("wire port-add", err)}}
	}
	p, err := c.srv.Manage.CreatePort(ctx, d, manage.PortInput{
		Name: in.Name, Protocol: store.Protocol(in.Protocol), LocalPort: in.LocalPort, Allow: allow, Port: in.Port,
	}, c.actor(g))
	if err != nil {
		return wire.PortReply{Reply: wire.Reply{Error: c.failure("wire port-add", err)}}
	}
	c.console.Printf("✔ created %s.%s: %s", p.Name, d.Name, c.srv.cfg.PortAddress(string(p.Protocol), p.Port))
	return wire.PortReply{Port: c.wirePort(p)}
}

func (c *clientConn) wirePortUpdate(payload []byte) wire.PortReply {
	var in wire.PortUpdate
	if err := json.Unmarshal(payload, &in); err != nil {
		return wire.PortReply{Reply: wire.Reply{Error: "bad request"}}
	}
	allow, ok := wire.ParseAllow(in.Allow)
	if !ok {
		return wire.PortReply{Reply: wire.Reply{Error: "say who may connect to " + in.Name + ": addresses or ranges, or any for anyone"}}
	}
	ctx, cancel := wireCtx()
	defer cancel()
	g, d, err := c.wireGrant(ctx, in.Subdomain)
	if err != nil {
		return wire.PortReply{Reply: wire.Reply{Error: c.failure("wire port-update", err)}}
	}
	p, err := c.portByName(ctx, d, in.Name)
	if err != nil {
		return wire.PortReply{Reply: wire.Reply{Error: c.failure("wire port-update", err)}}
	}
	p, err = c.srv.Manage.UpdatePort(ctx, d, p.ID, manage.PortInput{Name: p.Name, LocalPort: max(p.LocalPort, 1), Allow: allow}, c.actor(g))
	if err != nil {
		return wire.PortReply{Reply: wire.Reply{Error: c.failure("wire port-update", err)}}
	}
	return wire.PortReply{Port: c.wirePort(p)}
}

func (c *clientConn) wirePortDelete(payload []byte) wire.Reply {
	var in wire.PortRef
	if err := json.Unmarshal(payload, &in); err != nil {
		return wire.Reply{Error: "bad request"}
	}
	ctx, cancel := wireCtx()
	defer cancel()
	g, d, err := c.wireGrant(ctx, in.Subdomain)
	if err != nil {
		return wire.Reply{Error: c.failure("wire port-delete", err)}
	}
	p, err := c.portByName(ctx, d, in.Name)
	if err != nil {
		return wire.Reply{Error: c.failure("wire port-delete", err)}
	}
	if err := c.srv.Manage.DeletePort(ctx, d, p.ID, c.actor(g)); err != nil {
		return wire.Reply{Error: c.failure("wire port-delete", err)}
	}
	return wire.Reply{}
}
