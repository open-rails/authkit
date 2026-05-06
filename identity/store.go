package identity

import (
	"context"
	"strings"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Store provides minimal identity lookups/mutations against profiles schema.
type Store struct {
	pg     *pgxpool.Pool
	schema string
}

func NewStore(pg *pgxpool.Pool, schema string) *Store {
	s := strings.TrimSpace(schema)
	if s == "" {
		s = "profiles"
	}
	return &Store{pg: pg, schema: s}
}

func (s *Store) usersTable() string { return s.schema + ".users" }
func (s *Store) orgsTable() string  { return s.schema + ".orgs" }

// GetEmailsByIDs returns user_id -> email.
func (s *Store) GetEmailsByIDs(ctx context.Context, ids []uuid.UUID) (map[uuid.UUID]string, error) {
	out := make(map[uuid.UUID]string, len(ids))
	if len(ids) == 0 || s.pg == nil {
		return out, nil
	}
	rows, err := s.pg.Query(ctx, `SELECT id, email FROM `+s.usersTable()+` WHERE id = ANY($1::uuid[])`, ids)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var id uuid.UUID
		var email string
		if err := rows.Scan(&id, &email); err != nil {
			return nil, err
		}
		out[id] = email
	}
	return out, nil
}

// GetUsernamesByIDs returns user_id -> username (empty if NULL).
func (s *Store) GetUsernamesByIDs(ctx context.Context, ids []uuid.UUID) (map[uuid.UUID]string, error) {
	out := make(map[uuid.UUID]string, len(ids))
	if len(ids) == 0 || s.pg == nil {
		return out, nil
	}
	rows, err := s.pg.Query(ctx, `SELECT id, username FROM `+s.usersTable()+` WHERE id = ANY($1::uuid[])`, ids)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var id uuid.UUID
		var username *string
		if err := rows.Scan(&id, &username); err != nil {
			return nil, err
		}
		if username != nil {
			out[id] = *username
		} else {
			out[id] = ""
		}
	}
	return out, nil
}

// GetUsersByIDs returns username+email pairs for given IDs.
func (s *Store) GetUsersByIDs(ctx context.Context, ids []uuid.UUID) (map[uuid.UUID]struct{ Username, Email string }, error) {
	out := make(map[uuid.UUID]struct{ Username, Email string }, len(ids))
	if len(ids) == 0 || s.pg == nil {
		return out, nil
	}
	rows, err := s.pg.Query(ctx, `SELECT id, username, email FROM `+s.usersTable()+` WHERE id = ANY($1::uuid[])`, ids)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var id uuid.UUID
		var email string
		var username *string
		if err := rows.Scan(&id, &username, &email); err != nil {
			return nil, err
		}
		uname := ""
		if username != nil {
			uname = *username
		}
		out[id] = struct{ Username, Email string }{Username: uname, Email: email}
	}
	return out, nil
}

func (s *Store) GetIDByUsername(ctx context.Context, username string) (uuid.UUID, error) {
	if s.pg == nil || strings.TrimSpace(username) == "" {
		return uuid.Nil, nil
	}
	var id uuid.UUID
	err := s.pg.QueryRow(ctx, `SELECT id FROM `+s.usersTable()+` WHERE username=$1 LIMIT 1`, username).Scan(&id)
	if err != nil {
		return uuid.Nil, err
	}
	return id, nil
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
	var u User
	err := s.pg.QueryRow(ctx, `SELECT id, email, username, email_verified FROM `+s.usersTable()+` WHERE id=$1 LIMIT 1`, id).Scan(&u.ID, &u.Email, &u.Username, &u.EmailVerified)
	if err != nil {
		return nil, err
	}
	return &u, nil
}

func (s *Store) UpdateEmail(ctx context.Context, id uuid.UUID, email string) error {
	if s.pg == nil || id == uuid.Nil || strings.TrimSpace(email) == "" {
		return nil
	}
	_, err := s.pg.Exec(ctx, `UPDATE `+s.usersTable()+` SET email=$2, updated_at=NOW() WHERE id=$1`, id, email)
	return err
}

func (s *Store) UpdateUsername(ctx context.Context, id uuid.UUID, username string) error {
	if s.pg == nil || id == uuid.Nil || strings.TrimSpace(username) == "" {
		return nil
	}
	_, err := s.pg.Exec(ctx, `UPDATE `+s.usersTable()+` SET username=$2, updated_at=NOW() WHERE id=$1`, id, username)
	return err
}
