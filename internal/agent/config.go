// Package agent is intergate-tunnel: the intergate client as a service that
// keeps the tunnels of one machine open, on one or several gates, as
// tunnels.yaml says.
package agent

import (
	"cmp"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"errors"
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"

	"golang.org/x/crypto/ssh"
	"gopkg.in/yaml.v3"

	"github.com/jgermade/intergate/internal/client"
)

// Config is tunnels.yaml: what this machine forwards, by gate. Ports are
// named as on the gate, which keeps their protocol, public number and allow
// list; here is only where each goes on this side.
type Config struct {
	// Key is the private key file this machine signs in with; relative to
	// the file's directory. Default: "key".
	Key   string           `yaml:"key,omitempty"`
	Gates map[string]*Gate `yaml:"gates"`

	path string
}

// Gate is one intergate server, by its domain.
type Gate struct {
	// Dashboard is where /client.json was read.
	Dashboard string `yaml:"dashboard,omitempty"`
	// Server is the SSH endpoint, host:port.
	Server string `yaml:"server"`
	// HostKey is the server's key fingerprint, pinned when added.
	HostKey string             `yaml:"host_key"`
	Tunnels map[string]*Tunnel `yaml:"tunnels"`
}

// Tunnel is what one subdomain forwards to this machine.
type Tunnel struct {
	// HTTP is the local port, or host:port, of the HTTP tunnel; empty for
	// none.
	HTTP string `yaml:"http,omitempty"`
	// TCP and UDP map a port's name to its local port, or host:port.
	TCP map[string]string `yaml:"tcp,omitempty"`
	UDP map[string]string `yaml:"udp,omitempty"`
}

// Forwards turns t into the client's, in a stable order.
func (t *Tunnel) Forwards() ([]client.Forward, error) {
	var out []client.Forward
	if t.HTTP != "" {
		f, err := client.ParseForward(client.HTTP, t.HTTP)
		if err != nil {
			return nil, err
		}
		out = append(out, f)
	}
	for _, kind := range []string{client.TCP, client.UDP} {
		m := t.TCP
		if kind == client.UDP {
			m = t.UDP
		}
		for _, name := range slices.Sorted(maps.Keys(m)) {
			f, err := client.ParseForward(kind, name+"="+m[name])
			if err != nil {
				return nil, err
			}
			out = append(out, f)
		}
	}
	return out, nil
}

// Empty reports whether t forwards nothing.
func (t *Tunnel) Empty() bool { return t.HTTP == "" && len(t.TCP) == 0 && len(t.UDP) == 0 }

// LoadConfig reads path; a missing file is an empty configuration.
func LoadConfig(path string) (*Config, error) {
	c := &Config{path: path}
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		c.Gates = map[string]*Gate{}
		return c, nil
	}
	if err != nil {
		return nil, err
	}
	if err := yaml.Unmarshal(b, c); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	if c.Gates == nil {
		c.Gates = map[string]*Gate{}
	}
	for domain, g := range c.Gates {
		if g == nil {
			return nil, fmt.Errorf("%s: gate %s is empty", path, domain)
		}
		if g.Tunnels == nil {
			g.Tunnels = map[string]*Tunnel{}
		}
		for name, t := range g.Tunnels {
			if t == nil {
				g.Tunnels[name] = &Tunnel{}
				continue
			}
			if _, err := t.Forwards(); err != nil {
				return nil, fmt.Errorf("%s: %s.%s: %w", path, name, domain, err)
			}
		}
	}
	return c, nil
}

// Path is the file c was read from.
func (c *Config) Path() string { return c.path }

// KeyPath is the private key's file.
func (c *Config) KeyPath() string {
	k := cmp.Or(c.Key, "key")
	if filepath.IsAbs(k) {
		return k
	}
	return filepath.Join(filepath.Dir(c.path), k)
}

// Save writes c, replacing the file at once.
func (c *Config) Save() error {
	b, err := yaml.Marshal(c)
	if err != nil {
		return err
	}
	b = append([]byte("# intergate-tunnel: what this machine forwards, by gate. `intergate-tunnel add`\n"+
		"# and `remove` change it; ports' protocols, numbers and allow lists live on the gate.\n"), b...)
	return writeFile(c.path, b, 0o640)
}

// writeFile replaces path with data, through a file beside it.
func writeFile(path string, data []byte, mode os.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Chmod(mode); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}

// Each calls fn for every tunnel, by gate and then subdomain.
func (c *Config) Each(fn func(domain string, g *Gate, sub string, t *Tunnel)) {
	for _, domain := range slices.Sorted(maps.Keys(c.Gates)) {
		g := c.Gates[domain]
		for _, sub := range slices.Sorted(maps.Keys(g.Tunnels)) {
			fn(domain, g, sub, g.Tunnels[sub])
		}
	}
}

// Host is a tunnel's full name: web1.gate.example.com.
func Host(sub, domain string) string { return sub + "." + domain }

// Find returns the gate and subdomain a host names: web1.gate.example.com,
// among the gates c has.
func (c *Config) Find(host string) (domain, sub string, ok bool) {
	host = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(host), "."))
	for d := range c.Gates {
		if s, found := strings.CutSuffix(host, "."+d); found && s != "" && !strings.Contains(s, ".") {
			return d, s, true
		}
	}
	return "", "", false
}

// LoadKey reads the private key, or creates an Ed25519 one if there is
// none. The file is readable by its owner and group only.
func (c *Config) LoadKey(create bool) (ssh.Signer, bool, error) {
	path := c.KeyPath()
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) && create {
		_, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return nil, false, err
		}
		host, _ := os.Hostname()
		block, err := ssh.MarshalPrivateKey(priv, "intergate-tunnel@"+host)
		if err != nil {
			return nil, false, err
		}
		if err := writeFile(path, pem.EncodeToMemory(block), 0o640); err != nil {
			return nil, false, err
		}
		s, err := ssh.NewSignerFromKey(priv)
		return s, true, err
	}
	if err != nil {
		return nil, false, err
	}
	s, err := ssh.ParsePrivateKey(b)
	if err != nil {
		return nil, false, fmt.Errorf("%s: %w", path, err)
	}
	return s, false, nil
}

// AuthorizedKey is the public half of s, as a dashboard takes it.
func AuthorizedKey(s ssh.Signer) string {
	host, _ := os.Hostname()
	return strings.TrimSpace(string(ssh.MarshalAuthorizedKey(s.PublicKey()))) + " intergate-tunnel@" + host
}

// localPort is the port of a forward's local address, for the gate's
// dashboard to show.
func localPort(local string) int {
	if n, err := strconv.Atoi(local); err == nil {
		return n
	}
	if i := strings.LastIndexByte(local, ':'); i >= 0 {
		n, _ := strconv.Atoi(local[i+1:])
		return n
	}
	return 0
}
