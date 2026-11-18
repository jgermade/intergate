package clientapp

import (
	"errors"
	"net"
	"strings"

	"golang.org/x/crypto/ssh"

	"github.com/jgermade/intergate/internal/client"
	"github.com/jgermade/intergate/internal/wire"
)

// The subdomain's ports on the gate, seen and changed with the same key
// and host key the app connects with: a key that opens a subdomain may
// manage its ports, within its owner's limits.

// dial signs in to the gate without forwarding anything.
func (a *App) dial() (*ssh.Client, Settings, error) {
	s := a.Settings()
	switch {
	case s.Server == "" || s.HostKey == "":
		return nil, s, errors.New("enter your intergate's address and look it up first")
	case s.Subdomain == "":
		return nil, s, errors.New("enter the subdomain")
	}
	var files []string
	if s.KeyFile != "" {
		files = []string{s.KeyFile}
	}
	auth, err := client.AuthMethods(files)
	if err != nil {
		return nil, s, err
	}
	check, err := client.HostKeyCheck(s.HostKey)
	if err != nil {
		return nil, s, err
	}
	server := s.Server
	if _, _, err := net.SplitHostPort(server); err != nil {
		server = net.JoinHostPort(server, "22")
	}
	c, err := client.Dial(server, s.Subdomain, auth, check)
	if err != nil && strings.Contains(err.Error(), "unable to authenticate") {
		err = errors.New("the gate doesn't know this key: add it to " + s.Subdomain + " in the dashboard")
	}
	return c, s, err
}

// Ports lists the subdomain's ports on the gate, with its owner's quota.
func (a *App) Ports() (*wire.Subdomain, error) {
	c, s, err := a.dial()
	if err != nil {
		return nil, err
	}
	defer c.Close()
	info, err := client.Info(c, s.Subdomain)
	if err != nil {
		return nil, err
	}
	if len(info.Subdomains) != 1 {
		return nil, errors.New("the gate didn't say anything about " + s.Subdomain)
	}
	return &info.Subdomains[0], nil
}

// AddPort creates a port of the subdomain on the gate.
func (a *App) AddPort(in wire.PortAdd) (*wire.Port, error) {
	c, s, err := a.dial()
	if err != nil {
		return nil, err
	}
	defer c.Close()
	in.Subdomain = s.Subdomain
	in.Name = strings.ToLower(strings.TrimSpace(in.Name))
	p, err := client.AddPort(c, in)
	if err == nil {
		a.Logf("created %s.%s: %s, open to %s", p.Name, s.Subdomain, p.Address, allowText(p.Allow))
	}
	return p, err
}

// SetPortAllow changes who may connect to one of the subdomain's ports.
func (a *App) SetPortAllow(name string, allow []string) (*wire.Port, error) {
	c, s, err := a.dial()
	if err != nil {
		return nil, err
	}
	defer c.Close()
	p, err := client.UpdatePort(c, wire.PortUpdate{PortRef: wire.PortRef{Subdomain: s.Subdomain, Name: name}, Allow: allow})
	if err == nil {
		a.Logf("%s.%s is open to %s", p.Name, s.Subdomain, allowText(p.Allow))
	}
	return p, err
}

// DeletePort deletes one of the subdomain's ports from the gate.
func (a *App) DeletePort(name string) error {
	c, s, err := a.dial()
	if err != nil {
		return err
	}
	defer c.Close()
	err = client.DeletePort(c, wire.PortRef{Subdomain: s.Subdomain, Name: name})
	if err == nil {
		a.Logf("deleted %s.%s from the gate", name, s.Subdomain)
	}
	return err
}

func allowText(allow []string) string {
	if len(allow) == 0 {
		return "anyone"
	}
	return strings.Join(allow, ", ")
}
