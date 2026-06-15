package core

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/open-rails/authkit/internal/db"
)

var (
	// ErrInvalidDelegatedUser indicates a malformed (issuer, subject) pair.
	ErrInvalidDelegatedUser = errors.New("invalid_delegated_user")
	// ErrDelegatedUserNotFound indicates no delegated_user matched.
	ErrDelegatedUserNotFound = errors.New("delegated_user_not_found")
)

// DelegatedUser is the cross-domain identity anchor for a federated end-user
// vouched for by a remote_application (#81): the stable OIDC tuple
// (remote_application_id, issuer, subject) plus first/last-seen. App + billing
// tables FK -> ID. AuthKit makes NO auth decision off this record; authorization
// rides the token only (#78's core finding stands).
type DelegatedUser struct {
	ID                  string
	RemoteApplicationID string
	Issuer              string
	Subject             string // STABLE merchant-supplied uuid, never a username
	FirstSeenAt         time.Time
	LastSeenAt          time.Time
}

// TouchDelegatedUser records that the remote_application identified by issuer
// vouched for subject, RETURNING the stable uuidv7 anchor id. The id is minted
// ONCE and idempotent on the UNIQUE(remote_application_id, subject) natural key;
// repeat calls bump last_seen_at and return the SAME id (callers stamp it, never
// recompute). WHICH remote_application is resolved from the validated issuer —
// never a token claim. Unknown/disabled issuers fail closed as invalid. This is
// NOT a verify-path coupling: auth rides the token only.
func (s *Service) TouchDelegatedUser(ctx context.Context, issuer, subject string) (string, error) {
	if err := s.requirePG(); err != nil {
		return "", err
	}
	issuer = strings.TrimSpace(issuer)
	subject = strings.TrimSpace(subject)
	if issuer == "" || subject == "" {
		return "", ErrInvalidDelegatedUser
	}
	ra, err := s.GetRemoteApplication(ctx, issuer)
	if err != nil {
		if errors.Is(err, ErrRemoteApplicationNotFound) {
			return "", ErrInvalidDelegatedUser
		}
		return "", err
	}
	if !ra.Enabled {
		return "", ErrInvalidDelegatedUser
	}
	row, err := s.q.DelegatedUserTouch(ctx, db.DelegatedUserTouchParams{RemoteApplicationID: ra.ID, Issuer: issuer, Subject: subject})
	if err != nil {
		// A uuid pointing at no remote_application (FK 23503) or malformed
		// (22P02) is an invalid credential, not an internal failure.
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && (pgErr.Code == "23503" || pgErr.Code == "22P02") {
			return "", ErrInvalidDelegatedUser
		}
		return "", err
	}
	return row.ID, nil
}

// GetDelegatedUser returns the delegated_user anchored at (issuer, subject), or
// ErrDelegatedUserNotFound. Read-only; no auth decision.
func (s *Service) GetDelegatedUser(ctx context.Context, issuer, subject string) (*DelegatedUser, error) {
	if err := s.requirePG(); err != nil {
		return nil, err
	}
	issuer = strings.TrimSpace(issuer)
	subject = strings.TrimSpace(subject)
	if issuer == "" || subject == "" {
		return nil, ErrInvalidDelegatedUser
	}
	ra, err := s.GetRemoteApplication(ctx, issuer)
	if err != nil {
		if errors.Is(err, ErrRemoteApplicationNotFound) {
			return nil, ErrDelegatedUserNotFound
		}
		return nil, err
	}
	row, err := s.q.DelegatedUserByAppSubject(ctx, db.DelegatedUserByAppSubjectParams{RemoteApplicationID: ra.ID, Subject: subject})
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrDelegatedUserNotFound
	}
	if err != nil {
		return nil, err
	}
	return &DelegatedUser{ID: row.ID, RemoteApplicationID: row.RemoteApplicationID, Issuer: row.Issuer, Subject: row.Subject, FirstSeenAt: row.FirstSeenAt, LastSeenAt: row.LastSeenAt}, nil
}

// ListDelegatedUsersForIssuer returns the delegated_users vouched for by the
// remote_application registered at issuer, most-recently-seen first.
func (s *Service) ListDelegatedUsersForIssuer(ctx context.Context, issuer string) ([]DelegatedUser, error) {
	if err := s.requirePG(); err != nil {
		return nil, err
	}
	issuer = strings.TrimSpace(issuer)
	if issuer == "" {
		return nil, ErrInvalidDelegatedUser
	}
	ra, err := s.GetRemoteApplication(ctx, issuer)
	if err != nil {
		return nil, err
	}
	rows, err := s.q.DelegatedUsersByApp(ctx, ra.ID)
	if err != nil {
		return nil, err
	}
	out := make([]DelegatedUser, 0, len(rows))
	for _, r := range rows {
		out = append(out, DelegatedUser{ID: r.ID, RemoteApplicationID: r.RemoteApplicationID, Issuer: r.Issuer, Subject: r.Subject, FirstSeenAt: r.FirstSeenAt, LastSeenAt: r.LastSeenAt})
	}
	return out, nil
}
