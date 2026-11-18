package client

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/jgermade/intergate/internal/wire"
)

// ErrUnsupported is returned when the server is too old to manage ports
// from the client.
var ErrUnsupported = errors.New("this intergate server can't manage ports from the client: update it, or use its dashboard")

// Requester sends SSH global requests: an *ssh.Client.
type Requester interface {
	SendRequest(name string, wantReply bool, payload []byte) (bool, []byte, error)
}

// request sends one wire request and decodes its reply into out, whose
// Error, if any, it returns.
func request(c Requester, name string, in any, out interface{ err() string }) error {
	ok, reply, err := c.SendRequest(name, true, wire.Marshal(in))
	if err != nil {
		return err
	}
	if !ok {
		return ErrUnsupported
	}
	if err := json.Unmarshal(reply, out); err != nil {
		return fmt.Errorf("unexpected reply to %s: %w", name, err)
	}
	if msg := out.err(); msg != "" {
		return errors.New(msg)
	}
	return nil
}

type infoReply struct{ wire.Info }

func (r *infoReply) err() string { return r.Error }

type portReply struct{ wire.PortReply }

func (r *portReply) err() string { return r.Error }

type plainReply struct{ wire.Reply }

func (r *plainReply) err() string { return r.Error }

// Info lists the subdomains the key may open with their ports, or only
// subdomain's.
func Info(c Requester, subdomain string) (*wire.Info, error) {
	var r infoReply
	if err := request(c, wire.InfoRequest, wire.InfoQuery{Subdomain: subdomain}, &r); err != nil {
		return nil, err
	}
	return &r.Info, nil
}

// AddPort creates a port. allow is who may connect: addresses or CIDRs,
// or wire.Anyone alone.
func AddPort(c Requester, in wire.PortAdd) (*wire.Port, error) {
	var r portReply
	if err := request(c, wire.PortAddRequest, in, &r); err != nil {
		return nil, err
	}
	return r.Port, nil
}

// UpdatePort changes who may connect to a port.
func UpdatePort(c Requester, in wire.PortUpdate) (*wire.Port, error) {
	var r portReply
	if err := request(c, wire.PortUpdateRequest, in, &r); err != nil {
		return nil, err
	}
	return r.Port, nil
}

// DeletePort deletes a port; its public number goes back to the range.
func DeletePort(c Requester, ref wire.PortRef) error {
	return request(c, wire.PortDeleteRequest, ref, &plainReply{})
}

// Dial connects to an intergate server without forwarding anything, to
// send requests such as Info. user is the subdomain, if there is one.
func Dial(server, user string, auth []ssh.AuthMethod, hostKey ssh.HostKeyCallback) (*ssh.Client, error) {
	if user == "" {
		user = "intergate"
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	nc, err := dialContext(ctx, "tcp", server)
	if err != nil {
		return nil, err
	}
	cc, chans, reqs, err := ssh.NewClientConn(nc, server, &ssh.ClientConfig{User: user, Auth: auth, HostKeyCallback: hostKey, Timeout: 15 * time.Second})
	if err != nil {
		nc.Close()
		return nil, err
	}
	return ssh.NewClient(cc, chans, reqs), nil
}
