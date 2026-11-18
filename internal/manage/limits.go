package manage

import (
	"context"
	"errors"

	"github.com/jgermade/intergate/internal/config"
	"github.com/jgermade/intergate/internal/store"
)

// maxLimit bounds the counts an administrator can give a user.
const maxLimit = 10000

// maxRanges bounds the port ranges of a user.
const maxRanges = 32

// Limits are what a user may have: the configuration's, or those an
// administrator set for them.
type Limits struct {
	Subdomains int
	Ports      int
	// Ranges are where their ports' numbers come from: tcp.ports, or the
	// part of it an administrator gave them.
	Ranges []config.PortRange
	// Custom* are set where the user's own limit replaces the
	// configuration's.
	CustomSubdomains bool
	CustomPorts      bool
	CustomRanges     bool
}

// Limits returns u's limits.
func (s *Service) Limits(u *store.User) Limits {
	l := Limits{Subdomains: s.cfg.Limits.SubdomainsPerUser, Ports: s.cfg.TCP.MaxPorts}
	if u.Limits.Subdomains != nil {
		l.Subdomains, l.CustomSubdomains = *u.Limits.Subdomains, true
	}
	if u.Limits.Ports != nil {
		l.Ports, l.CustomPorts = *u.Limits.Ports, true
	}
	first, last := s.cfg.TCP.Range()
	if ranges, err := config.ParsePortRanges(u.Limits.PortRanges); err == nil && len(ranges) > 0 {
		// tcp.ports may have shrunk since: only its part counts.
		for _, r := range ranges {
			r.First, r.Last = max(r.First, first), min(r.Last, last)
			if r.First <= r.Last {
				l.Ranges = append(l.Ranges, r)
			}
		}
		l.CustomRanges = true
	} else if first != 0 {
		l.Ranges = []config.PortRange{{First: first, Last: last}}
	}
	return l
}

// LimitsInput sets a user's limits; a nil count goes back to the
// configuration's, and empty Ranges to all of tcp.ports.
type LimitsInput struct {
	Subdomains *int
	Ports      *int
	Ranges     string
}

// SetUserLimits changes the limits of a user. What they already have is
// kept even when it goes over: they just can't add more.
func (s *Service) SetUserLimits(ctx context.Context, userID int64, in LimitsInput, actor string) error {
	for _, n := range []*int{in.Subdomains, in.Ports} {
		if n != nil && (*n < 0 || *n > maxLimit) {
			return Errorf("a limit must be between 0 and %d", maxLimit)
		}
	}
	ranges, err := config.ParsePortRanges(in.Ranges)
	if err != nil {
		return Errorf("%v", err)
	}
	if len(ranges) > maxRanges {
		return Errorf("a user can have at most %d port ranges", maxRanges)
	}
	if len(ranges) > 0 && !s.cfg.TCP.Enabled() {
		return Errorf("this server has no TCP ports (tcp.ports in its configuration) to give ranges of")
	}
	first, last := s.cfg.TCP.Range()
	for _, r := range ranges {
		if r.First < first || r.Last > last {
			return Errorf("%s is outside this server's ports, %d-%d", r, first, last)
		}
	}
	l := store.UserLimits{Subdomains: in.Subdomains, Ports: in.Ports, PortRanges: config.FormatPortRanges(ranges)}
	err = s.store.SetUserLimits(ctx, userID, l)
	if errors.Is(err, store.ErrNotFound) {
		return Errorf("that user no longer exists")
	}
	if err != nil {
		return err
	}
	s.log.Info("user limits set", "user_id", userID, "subdomains", show(in.Subdomains), "ports", show(in.Ports), "ranges", l.PortRanges, "by", actor)
	return nil
}

func show(n *int) any {
	if n == nil {
		return "default"
	}
	return *n
}

// spans turns ranges into the store's.
func spans(ranges []config.PortRange) []store.Span {
	out := make([]store.Span, len(ranges))
	for i, r := range ranges {
		out[i] = store.Span{First: r.First, Last: r.Last}
	}
	return out
}

func inRanges(ranges []config.PortRange, port int) bool {
	for _, r := range ranges {
		if r.Contains(port) {
			return true
		}
	}
	return false
}

// PortQuota is how many ports d's owner has, across their subdomains, and
// their limits.
func (s *Service) PortQuota(ctx context.Context, d *store.Subdomain) (used int, l Limits, err error) {
	owner, err := s.store.UserByID(ctx, d.UserID)
	if err != nil {
		return 0, Limits{}, err
	}
	used, err = s.store.CountPortsByUser(ctx, owner.ID)
	return used, s.Limits(owner), err
}
