package store

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"time"
)

// Guest is someone besides its owner who may open a private subdomain,
// once signed in with this email.
type Guest struct {
	ID          int64
	SubdomainID int64
	Email       string
	CreatedAt   time.Time
}

// AddGuest lets email open a private subdomain. The email must already be
// validated. It returns ErrConflict if it is there already.
func (s *Store) AddGuest(ctx context.Context, subdomainID int64, email string) (*Guest, error) {
	g := &Guest{SubdomainID: subdomainID, Email: NormalizeEmail(email), CreatedAt: s.now().Truncate(time.Second)}
	err := s.db.QueryRowContext(ctx, `
		INSERT INTO subdomain_guests (subdomain_id, email, created_at)
		VALUES (?, ?, ?) RETURNING id`,
		g.SubdomainID, g.Email, unix(g.CreatedAt)).Scan(&g.ID)
	if isUniqueViolation(err) {
		return nil, ErrConflict
	}
	if err != nil {
		return nil, err
	}
	return g, nil
}

// GuestsBySubdomain lists who besides its owner may open a subdomain, in
// the order they were added.
func (s *Store) GuestsBySubdomain(ctx context.Context, subdomainID int64) ([]*Guest, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, subdomain_id, email, created_at FROM subdomain_guests
		WHERE subdomain_id = ? ORDER BY created_at, id`, subdomainID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*Guest
	for rows.Next() {
		var g Guest
		var created int64
		if err := rows.Scan(&g.ID, &g.SubdomainID, &g.Email, &created); err != nil {
			return nil, err
		}
		g.CreatedAt = fromUnix(created)
		out = append(out, &g)
	}
	return out, rows.Err()
}

// DeleteGuest removes someone from a subdomain's guests and returns them.
func (s *Store) DeleteGuest(ctx context.Context, subdomainID, guestID int64) (*Guest, error) {
	var g Guest
	var created int64
	err := s.db.QueryRowContext(ctx, `
		DELETE FROM subdomain_guests WHERE id = ? AND subdomain_id = ?
		RETURNING id, subdomain_id, email, created_at`,
		guestID, subdomainID).Scan(&g.ID, &g.SubdomainID, &g.Email, &created)
	if err != nil {
		return nil, notFound(err)
	}
	g.CreatedAt = fromUnix(created)
	return &g, nil
}

// IsGuest reports whether email is one of a subdomain's guests.
func (s *Store) IsGuest(ctx context.Context, subdomainID int64, email string) (bool, error) {
	var found int
	err := s.db.QueryRowContext(ctx, `
		SELECT 1 FROM subdomain_guests WHERE subdomain_id = ? AND email = ?`,
		subdomainID, NormalizeEmail(email)).Scan(&found)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	return err == nil, err
}

// GuestCandidates lists enabled accounts whose email or name contains q,
// for suggestions on a subdomain: not its owner nor its guests. Emails
// starting with q come first, then who signed in last. At most limit.
func (s *Store) GuestCandidates(ctx context.Context, subdomainID int64, q string, limit int) ([]*User, error) {
	like := "%" + escapeLike(strings.ToLower(strings.TrimSpace(q))) + "%"
	prefix := escapeLike(strings.ToLower(strings.TrimSpace(q))) + "%"
	rows, err := s.db.QueryContext(ctx, `
		SELECT `+userColumns+` FROM users
		WHERE disabled = 0
			AND id != (SELECT user_id FROM subdomains WHERE id = ?)
			AND email NOT IN (SELECT email FROM subdomain_guests WHERE subdomain_id = ?)
			AND (email LIKE ? ESCAPE '\' OR name LIKE ? ESCAPE '\')
		ORDER BY email LIKE ? ESCAPE '\' DESC, last_login_at DESC, email
		LIMIT ?`, subdomainID, subdomainID, like, like, prefix, limit)
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

// escapeLike makes s match itself in a LIKE pattern with ESCAPE '\'.
func escapeLike(s string) string {
	return strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`).Replace(s)
}
