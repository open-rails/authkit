package identity

import (
	"context"
	"strings"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/open-rails/authkit/internal/db"
)

// Store provides minimal identity lookups/mutations against the profiles schema.
type Store struct {
	pg *pgxpool.Pool
	q  *db.Queries
}

func NewStore(pg *pgxpool.Pool) *Store {
	return &Store{pg: pg, q: db.New(pg)}
}

// GetEmailsByIDs returns user_id -> email.
func (s *Store) GetEmailsByIDs(ctx context.Context, ids []uuid.UUID) (map[uuid.UUID]string, error) {
	out := make(map[uuid.UUID]string, len(ids))
	if len(ids) == 0 || s.pg == nil {
		return out, nil
	}
	rows, err := s.q.IdentityUsersByIDs(ctx, uuidStrings(ids))
	if err != nil {
		return nil, err
	}
	for _, r := range rows {
		id, err := uuid.Parse(r.ID)
		if err != nil {
			return nil, err
		}
		out[id] = deref(r.Email)
	}
	return out, nil
}

// GetUsernamesByIDs returns user_id -> username (empty if NULL).
func (s *Store) GetUsernamesByIDs(ctx context.Context, ids []uuid.UUID) (map[uuid.UUID]string, error) {
	out := make(map[uuid.UUID]string, len(ids))
	if len(ids) == 0 || s.pg == nil {
		return out, nil
	}
	rows, err := s.q.IdentityUsersByIDs(ctx, uuidStrings(ids))
	if err != nil {
		return nil, err
	}
	for _, r := range rows {
		id, err := uuid.Parse(r.ID)
		if err != nil {
			return nil, err
		}
		out[id] = deref(r.Username)
	}
	return out, nil
}

// GetUsersByIDs returns username+email pairs for given IDs.
func (s *Store) GetUsersByIDs(ctx context.Context, ids []uuid.UUID) (map[uuid.UUID]struct{ Username, Email string }, error) {
	out := make(map[uuid.UUID]struct{ Username, Email string }, len(ids))
	if len(ids) == 0 || s.pg == nil {
		return out, nil
	}
	rows, err := s.q.IdentityUsersByIDs(ctx, uuidStrings(ids))
	if err != nil {
		return nil, err
	}
	for _, r := range rows {
		id, err := uuid.Parse(r.ID)
		if err != nil {
			return nil, err
		}
		out[id] = struct{ Username, Email string }{Username: deref(r.Username), Email: deref(r.Email)}
	}
	return out, nil
}

func (s *Store) GetIDByUsername(ctx context.Context, username string) (uuid.UUID, error) {
	if s.pg == nil || strings.TrimSpace(username) == "" {
		return uuid.Nil, nil
	}
	idStr, err := s.q.IdentityUserIDByUsername(ctx, &username)
	if err != nil {
		return uuid.Nil, err
	}
	return uuid.Parse(idStr)
}

type User struct {
	ID            uuid.UUID
	Email         string
	Username      *string
	EmailVerified bool
}

func (s *Store) GetByID(ctx context.Context, id uuid.UUID) (*User, error) {
	if s.pg == nil || id == uuid.Nil {
		return nil, nil
	}
	row, err := s.q.IdentityUserByID(ctx, id.String())
	if err != nil {
		return nil, err
	}
	uid, err := uuid.Parse(row.ID)
	if err != nil {
		return nil, err
	}
	return &User{ID: uid, Email: deref(row.Email), Username: row.Username, EmailVerified: row.EmailVerified}, nil
}

func (s *Store) UpdateEmail(ctx context.Context, id uuid.UUID, email string) error {
	if s.pg == nil || id == uuid.Nil || strings.TrimSpace(email) == "" {
		return nil
	}
	return s.q.IdentityUpdateUserEmail(ctx, db.IdentityUpdateUserEmailParams{ID: id.String(), Email: &email})
}

func (s *Store) UpdateUsername(ctx context.Context, id uuid.UUID, username string) error {
	if s.pg == nil || id == uuid.Nil || strings.TrimSpace(username) == "" {
		return nil
	}
	return s.q.IdentityUpdateUserUsername(ctx, db.IdentityUpdateUserUsernameParams{ID: id.String(), Username: &username})
}

func uuidStrings(ids []uuid.UUID) []string {
	out := make([]string, len(ids))
	for i, id := range ids {
		out[i] = id.String()
	}
	return out
}

func deref(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}
