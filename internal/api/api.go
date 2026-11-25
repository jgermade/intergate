// Package api holds the JSON shapes that both the dashboard's API and the
// admin socket answer with, and their conversions from stored records, so
// the browser and `intergate config` read the same thing.
package api

import (
	"time"

	"github.com/jgermade/intergate/internal/config"
	"github.com/jgermade/intergate/internal/manage"
	"github.com/jgermade/intergate/internal/ports"
	"github.com/jgermade/intergate/internal/store"
	"github.com/jgermade/intergate/internal/tunnel"
)

// Subdomain is a registered subdomain and its live tunnel, if any.
type Subdomain struct {
	Name      string        `json:"name"`
	URL       string        `json:"url"`
	Owner     string        `json:"owner"`
	Access    store.Access  `json:"access"`
	Keys      int           `json:"keys"`
	CreatedAt time.Time     `json:"created_at"`
	Tunnel    *tunnel.Stats `json:"tunnel,omitempty"`
	// Ports counts its TCP ports, and PortsOnline those forwarded now.
	Ports       int `json:"ports"`
	PortsOnline int `json:"ports_online"`
	// Guests counts who besides its owner may open it while private.
	Guests int `json:"guests"`
}

// NewSubdomain describes d; t is its tunnel, or nil when offline.
func NewSubdomain(cfg *config.Config, d *store.Subdomain, t *tunnel.Stats) Subdomain {
	return Subdomain{
		Name:      d.Name,
		URL:       cfg.TunnelURL(d.Name),
		Owner:     d.OwnerEmail,
		Access:    d.Access,
		Keys:      d.Keys,
		CreatedAt: d.CreatedAt,
		Tunnel:    t,
		Ports:     d.Ports,
		Guests:    d.Guests,
	}
}

// Port is a TCP port of a subdomain, and its forward when a client has it
// open.
type Port struct {
	ID        int64          `json:"id"`
	Name      string         `json:"name"`
	Protocol  store.Protocol `json:"protocol"`
	Port      int            `json:"port"`
	Address   string         `json:"address"`
	Allow     []string       `json:"allow"`
	Preset    string         `json:"preset"`
	LocalPort int            `json:"local_port"`
	CreatedBy string         `json:"created_by"`
	CreatedAt time.Time      `json:"created_at"`
	Forward   *ports.Stats   `json:"forward,omitempty"`
}

// NewPort describes p; f is its forward, or nil.
func NewPort(cfg *config.Config, p *store.Port, f *ports.Stats) Port {
	allow := p.Allow
	if allow == nil {
		allow = []string{}
	}
	return Port{
		ID: p.ID, Name: p.Name, Protocol: p.Protocol, Port: p.Port, Address: cfg.PortAddress(string(p.Protocol), p.Port),
		Allow: allow, Preset: p.Preset, LocalPort: p.LocalPort, CreatedBy: p.CreatedBy, CreatedAt: p.CreatedAt, Forward: f,
	}
}

// Key is an SSH key authorized on a subdomain.
type Key struct {
	ID          int64     `json:"id"`
	Name        string    `json:"name"`
	Type        string    `json:"type"`
	Fingerprint string    `json:"fingerprint"`
	CreatedAt   time.Time `json:"created_at"`
	LastUsedAt  time.Time `json:"last_used_at"`
	// FromAccount is set for a key added from an account's keys: it goes
	// when the account's does.
	FromAccount bool `json:"from_account,omitempty"`
}

// NewKey describes k, without the key itself.
func NewKey(k *store.Key) Key {
	return Key{ID: k.ID, Name: k.Name, Type: k.Type(), Fingerprint: k.Fingerprint, CreatedAt: k.CreatedAt, LastUsedAt: k.LastUsedAt, FromAccount: k.UserKeyID != 0}
}

// NewKeys describes keys; never nil, so it encodes as [].
func NewKeys(keys []*store.Key) []Key {
	out := make([]Key, len(keys))
	for i, k := range keys {
		out[i] = NewKey(k)
	}
	return out
}

// AccountKey is an SSH key of an account, without the key itself.
type AccountKey struct {
	ID          int64     `json:"id"`
	Name        string    `json:"name"`
	Type        string    `json:"type"`
	Fingerprint string    `json:"fingerprint"`
	CreatedAt   time.Time `json:"created_at"`
	// Subdomains are those it was added to.
	Subdomains []string `json:"subdomains"`
}

// NewAccountKeys describes an account's keys and the subdomains each was
// added to; never nil, so it encodes as [].
func NewAccountKeys(keys []*store.UserKey, attached []store.Attachment) []AccountKey {
	out := make([]AccountKey, 0, len(keys))
	for _, k := range keys {
		v := AccountKey{ID: k.ID, Name: k.Name, Type: k.Type(), Fingerprint: k.Fingerprint, CreatedAt: k.CreatedAt, Subdomains: []string{}}
		for _, a := range attached {
			if a.UserKeyID == k.ID {
				v.Subdomains = append(v.Subdomains, a.Subdomain)
			}
		}
		out = append(out, v)
	}
	return out
}

// Guest is someone besides its owner who may open a private subdomain.
type Guest struct {
	ID        int64     `json:"id"`
	Email     string    `json:"email"`
	CreatedAt time.Time `json:"created_at"`
}

// NewGuest describes g.
func NewGuest(g *store.Guest) Guest {
	return Guest{ID: g.ID, Email: g.Email, CreatedAt: g.CreatedAt}
}

// NewGuests describes guests; never nil, so it encodes as [].
func NewGuests(guests []*store.Guest) []Guest {
	out := make([]Guest, len(guests))
	for i, g := range guests {
		out[i] = NewGuest(g)
	}
	return out
}

// SubdomainDetail is a subdomain with its keys, ports and guests.
type SubdomainDetail struct {
	Subdomain
	KeyList   []Key   `json:"key_list"`
	PortList  []Port  `json:"port_list"`
	GuestList []Guest `json:"guest_list"`
}

// User is an account.
type User struct {
	ID       int64  `json:"id"`
	Email    string `json:"email"`
	Name     string `json:"name"`
	Disabled bool   `json:"disabled"`
	Admin    bool   `json:"admin"`
	Role     string `json:"role"`
	// ConfigOwner is set when auth.admins makes the user an owner, which
	// the dashboard cannot change.
	ConfigOwner bool      `json:"config_owner"`
	Allowed     bool      `json:"allowed"`
	Subdomains  int       `json:"subdomains"`
	Ports       int       `json:"ports"`
	Passkeys    int       `json:"passkeys"`
	Providers   string    `json:"providers"`
	LastLoginAt time.Time `json:"last_login_at"`
	Limits      Limits    `json:"limits"`
}

// Limits are what a user may have, and which of them an administrator
// set for them rather than the configuration.
type Limits struct {
	Subdomains int `json:"subdomains"`
	Ports      int `json:"ports"`
	// Ranges are where their ports' numbers come from, like
	// "30100-30109,30200-30299".
	Ranges           string `json:"ranges"`
	CustomSubdomains bool   `json:"custom_subdomains"`
	CustomPorts      bool   `json:"custom_ports"`
	CustomRanges     bool   `json:"custom_ranges"`
}

// NewLimits describes l.
func NewLimits(l manage.Limits) Limits {
	return Limits{
		Subdomains: l.Subdomains, Ports: l.Ports, Ranges: config.FormatPortRanges(l.Ranges),
		CustomSubdomains: l.CustomSubdomains, CustomPorts: l.CustomPorts, CustomRanges: l.CustomRanges,
	}
}

// NewUser describes u, whose limits are l, as an administrator sees it.
func NewUser(cfg *config.Config, u store.UserSummary, l manage.Limits) User {
	role := cfg.UserRole(u.Email, string(u.Role))
	return User{
		ID: u.ID, Email: u.Email, Name: u.Name, Disabled: u.Disabled,
		Admin: role != "user", Role: role, ConfigOwner: cfg.IsAdmin(u.Email), Allowed: cfg.UserAllowed(u.Email, u.Added, string(u.Role)),
		Subdomains: u.Subdomains, Ports: u.Ports, Passkeys: u.Passkeys, Providers: u.Providers, LastLoginAt: u.LastLoginAt,
		Limits: NewLimits(l),
	}
}

// KeysResult reports keys added in authorized_keys format: how many, and
// why the others were not.
type KeysResult struct {
	Added    int      `json:"added"`
	Problems []string `json:"problems,omitempty"`
}
