package store

import (
	"context"
	"time"
)

// Guest is an account besides its owner that may open a private
// subdomain.
type Guest struct {
	ID          int64
	SubdomainID int64
	UserID      int64
	Email       string
	Name        string
	AvatarURL   string
	CreatedAt   time.Time
}

const guestQuery = `
	SELECT g.id, g.subdomain_id, g.user_id, u.email, u.name, u.avatar_url, g.created_at
	FROM subdomain_guests g JOIN users u ON u.id = g.user_id `

func scanGuest(row scanner) (*Guest, error) {
	var g Guest
	var created int64
	if err := row.Scan(&g.ID, &g.SubdomainID, &g.UserID, &g.Email, &g.Name, &g.AvatarURL, &created); err != nil {
		return nil, notFound(err)
	}
	g.CreatedAt = fromUnix(created)
	return &g, nil
}

// AddGuest lets an account open a private subdomain. It returns
// ErrConflict if it may already.
func (s *Store) AddGuest(ctx context.Context, subdomainID, userID int64) (*Guest, error) {
	var id int64
	err := s.db.QueryRowContext(ctx, `
		INSERT INTO subdomain_guests (subdomain_id, user_id, created_at)
		VALUES (?, ?, ?) RETURNING id`,
		subdomainID, userID, unix(s.now())).Scan(&id)
	if isUniqueViolation(err) {
		return nil, ErrConflict
	}
	if err != nil {
		return nil, err
	}
	return scanGuest(s.db.QueryRowContext(ctx, guestQuery+`WHERE g.id = ?`, id))
}

// GuestsBySubdomain lists who besides its owner may open a subdomain, in
// the order they were added.
func (s *Store) GuestsBySubdomain(ctx context.Context, subdomainID int64) ([]*Guest, error) {
	rows, err := s.db.QueryContext(ctx, guestQuery+`WHERE g.subdomain_id = ? ORDER BY g.created_at, g.id`, subdomainID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*Guest
	for rows.Next() {
		g, err := scanGuest(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, g)
	}
	return out, rows.Err()
}

// DeleteGuest removes someone from a subdomain's guests and returns them.
func (s *Store) DeleteGuest(ctx context.Context, subdomainID, guestID int64) (*Guest, error) {
	g, err := scanGuest(s.db.QueryRowContext(ctx, guestQuery+`WHERE g.id = ? AND g.subdomain_id = ?`, guestID, subdomainID))
	if err != nil {
		return nil, err
	}
	res, err := s.db.ExecContext(ctx, `DELETE FROM subdomain_guests WHERE id = ?`, g.ID)
	if err != nil {
		return nil, err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return nil, ErrNotFound
	}
	return g, nil
}

// IsGuest reports whether an account is one of a subdomain's guests.
func (s *Store) IsGuest(ctx context.Context, subdomainID, userID int64) (bool, error) {
	var ok bool
	err := s.db.QueryRowContext(ctx, `
		SELECT EXISTS(SELECT 1 FROM subdomain_guests WHERE subdomain_id = ? AND user_id = ?)`,
		subdomainID, userID).Scan(&ok)
	return ok, err
}

// GuestCandidates lists the enabled accounts that could be added to a
// subdomain: not its owner nor its guests, by name (or email when they
// have none).
func (s *Store) GuestCandidates(ctx context.Context, subdomainID int64) ([]*User, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT `+userColumns+` FROM users
		WHERE disabled = 0
			AND id != (SELECT user_id FROM subdomains WHERE id = ?)
			AND id NOT IN (SELECT user_id FROM subdomain_guests WHERE subdomain_id = ?)
		ORDER BY lower(CASE name WHEN '' THEN email ELSE name END), email`, subdomainID, subdomainID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*User
	for rows.Next() {
		u, err := scanUser(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, u)
	}
	return out, rows.Err()
}

// Invitation is a subdomain a user was invited to open, with what decides
// whether the invitation lets them in now.
type Invitation struct {
	SubdomainID int64
	Subdomain   string
	Access      Access
	Owner       User
	InvitedAt   time.Time
}

// InvitationsFor lists the subdomains userID was invited to, by name,
// leaving out those of disabled owners.
func (s *Store) InvitationsFor(ctx context.Context, userID int64) ([]Invitation, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT d.id, d.name, d.access, u.id, u.email, u.name, u.added, u.role, u.can_invite, g.created_at
		FROM subdomain_guests g
		JOIN subdomains d ON d.id = g.subdomain_id
		JOIN users u ON u.id = d.user_id
		WHERE g.user_id = ? AND u.disabled = 0
		ORDER BY d.name`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Invitation
	for rows.Next() {
		var in Invitation
		var invited int64
		o := &in.Owner
		if err := rows.Scan(&in.SubdomainID, &in.Subdomain, &in.Access, &o.ID, &o.Email, &o.Name, &o.Added, &o.Role, &o.CanInvite, &invited); err != nil {
			return nil, err
		}
		in.InvitedAt = fromUnix(invited)
		out = append(out, in)
	}
	return out, rows.Err()
}
