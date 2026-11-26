package manage

import (
	"context"
	"errors"

	"github.com/jgermade/intergate/internal/store"
)

// GuestsPerSubdomain is how many people besides its owner may open a
// private subdomain.
const GuestsPerSubdomain = 50

// MayInvite reports whether u may share their private subdomains with
// other accounts: admins and owners always, users when an administrator
// lets them.
func (s *Service) MayInvite(u *store.User) bool {
	return u.CanInvite || s.cfg.UserRole(u.Email, string(u.Role)) != string(store.RoleUser)
}

// OwnerMayInvite reports whether d's owner may share it. While they may
// not, its guests can't open it, though they stay on its list.
func (s *Service) OwnerMayInvite(ctx context.Context, d *store.Subdomain) (bool, error) {
	owner, err := s.store.UserByID(ctx, d.UserID)
	if err != nil {
		return false, err
	}
	return s.MayInvite(owner), nil
}

// AddGuest lets an existing account, by id or else by email, open d while
// it is private, once signed in. Its owner must be allowed to invite, and
// the account to sign in. Opening is checked on every request, so it takes
// effect at once.
func (s *Service) AddGuest(ctx context.Context, d *store.Subdomain, userID int64, email, actor string) (*store.Guest, error) {
	may, err := s.OwnerMayInvite(ctx, d)
	if err != nil {
		return nil, err
	}
	if !may {
		return nil, Errorf("the owner, %s, may not invite other users: an administrator can allow it in their options", d.OwnerEmail)
	}
	var u *store.User
	if userID != 0 {
		u, err = s.store.UserByID(ctx, userID)
	} else {
		email = store.NormalizeEmail(email)
		if err := validEmail(email); err != nil {
			return nil, err
		}
		u, err = s.store.UserByEmail(ctx, email)
	}
	switch {
	case errors.Is(err, store.ErrNotFound) && userID != 0:
		return nil, Errorf("that user no longer exists")
	case errors.Is(err, store.ErrNotFound):
		return nil, Errorf("there is no account for %s: only existing users can be invited", email)
	case err != nil:
		return nil, err
	case u.ID == d.UserID:
		return nil, Errorf("the owner, %s, can always open %s.%s", u.Email, d.Name, s.cfg.Domain())
	case u.Disabled:
		return nil, Errorf("the account %s is disabled", u.Email)
	case !s.cfg.UserAllowed(u.Email, u.Added, string(u.Role)):
		return nil, Errorf("the account %s may not sign in to this intergate", u.Email)
	}
	guests, err := s.store.GuestsBySubdomain(ctx, d.ID)
	if err != nil {
		return nil, err
	}
	if len(guests) >= GuestsPerSubdomain {
		return nil, Errorf("a subdomain can be shared with at most %d people", GuestsPerSubdomain)
	}
	g, err := s.store.AddGuest(ctx, d.ID, u.ID)
	if errors.Is(err, store.ErrConflict) {
		return nil, Errorf("it is already open to %s", u.Email)
	}
	if err != nil {
		return nil, err
	}
	s.log.Info("guest added", "subdomain", d.Name, "email", u.Email, "by", actor)
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

// GuestCandidates lists the accounts that could be added to d: enabled,
// allowed to sign in, and neither its owner nor there already.
func (s *Service) GuestCandidates(ctx context.Context, d *store.Subdomain) ([]*store.User, error) {
	users, err := s.store.GuestCandidates(ctx, d.ID)
	if err != nil {
		return nil, err
	}
	out := users[:0]
	for _, u := range users {
		if s.cfg.UserAllowed(u.Email, u.Added, string(u.Role)) {
			out = append(out, u)
		}
	}
	return out, nil
}

// SetUserCanInvite lets a user share their private subdomains with other
// accounts, or stops them: their guests then can't open them until it is
// allowed again.
func (s *Service) SetUserCanInvite(ctx context.Context, userID int64, can bool, actor string) error {
	err := s.store.SetUserCanInvite(ctx, userID, can)
	if errors.Is(err, store.ErrNotFound) {
		return Errorf("user not found")
	}
	if err != nil {
		return err
	}
	s.log.Info("user updated", "user_id", userID, "can_invite", can, "by", actor)
	return nil
}

// SharedWith lists the subdomains u was invited to and may open now: those
// of owners who may sign in, and, while private, may invite.
func (s *Service) SharedWith(ctx context.Context, u *store.User) ([]store.Invitation, error) {
	list, err := s.store.InvitationsFor(ctx, u.ID)
	if err != nil {
		return nil, err
	}
	out := list[:0]
	for _, in := range list {
		o := &in.Owner
		if !s.cfg.UserAllowed(o.Email, o.Added, string(o.Role)) {
			continue
		}
		if in.Access == store.AccessPrivate && !s.MayInvite(o) {
			continue
		}
		out = append(out, in)
	}
	return out, nil
}
