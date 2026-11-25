package manage

import (
	"context"
	"errors"
	"strings"

	"github.com/jgermade/intergate/internal/store"
)

// GuestsPerSubdomain is how many people besides its owner may open a
// private subdomain.
const GuestsPerSubdomain = 50

// AddGuest lets email open d while it is private, once signed in with that
// email. It gives no right to sign in: someone the configuration does not
// allow, nor an administrator added, still can't. Opening is checked on
// every request, so it takes effect at once.
func (s *Service) AddGuest(ctx context.Context, d *store.Subdomain, email, actor string) (*store.Guest, error) {
	email = store.NormalizeEmail(email)
	if err := validEmail(email); err != nil {
		return nil, err
	}
	if email == store.NormalizeEmail(d.OwnerEmail) {
		return nil, Errorf("the owner, %s, can always open %s.%s", email, d.Name, s.cfg.Domain())
	}
	guests, err := s.store.GuestsBySubdomain(ctx, d.ID)
	if err != nil {
		return nil, err
	}
	if len(guests) >= GuestsPerSubdomain {
		return nil, Errorf("a subdomain can be shared with at most %d people", GuestsPerSubdomain)
	}
	g, err := s.store.AddGuest(ctx, d.ID, email)
	if errors.Is(err, store.ErrConflict) {
		return nil, Errorf("it is already open to %s", email)
	}
	if err != nil {
		return nil, err
	}
	s.log.Info("guest added", "subdomain", d.Name, "email", email, "by", actor)
	return g, nil
}

// RemoveGuest stops a guest from opening d, from their next request on.
func (s *Service) RemoveGuest(ctx context.Context, d *store.Subdomain, guestID int64, actor string) (*store.Guest, error) {
	g, err := s.store.DeleteGuest(ctx, d.ID, guestID)
	if errors.Is(err, store.ErrNotFound) {
		return nil, Errorf("that person was already removed")
	}
	if err != nil {
		return nil, err
	}
	s.log.Info("guest removed", "subdomain", d.Name, "email", g.Email, "by", actor)
	return g, nil
}

// GuestSuggestionsLimit is how many accounts GuestSuggestions returns.
const GuestSuggestionsLimit = 8

// GuestSuggestions lists accounts that could be added to d, for a
// typeahead: those whose email or name contains q, that may sign in, and
// are neither its owner nor already there.
func (s *Service) GuestSuggestions(ctx context.Context, d *store.Subdomain, q string) ([]*store.User, error) {
	if q = strings.TrimSpace(q); q == "" {
		return nil, nil
	}
	// Some of them may not sign in: ask for more than are shown.
	users, err := s.store.GuestCandidates(ctx, d.ID, q, 5*GuestSuggestionsLimit)
	if err != nil {
		return nil, err
	}
	out := make([]*store.User, 0, GuestSuggestionsLimit)
	for _, u := range users {
		if s.cfg.UserAllowed(u.Email, u.Added, string(u.Role)) {
			if out = append(out, u); len(out) == GuestSuggestionsLimit {
				break
			}
		}
	}
	return out, nil
}
