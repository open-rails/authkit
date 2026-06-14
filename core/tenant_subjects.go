package core

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgconn"

	"github.com/open-rails/authkit/internal/db"
)

var ErrInvalidTenantSubject = errors.New("invalid_tenant_subject")

// TenantSubject is the minimal local record for an external OIDC subject a
// remote_application vouched for. These are NOT local users and NOT members:
// AuthKit stores only the stable OIDC identity tuple (remote_application_id,
// issuer, subject) plus first/last-seen timestamps. Their permissions ride on
// the delegated token (#75), never stored here.
type TenantSubject struct {
	ID                  string
	RemoteApplicationID string
	Issuer              string
	Subject             string
	CreatedAt           time.Time
	LastSeenAt          time.Time
}

// TouchTenantSubjectForIssuer records that the remote_application identified by
// issuer accepted subject, resolving WHICH remote_application from the issuer —
// never from a token claim. Delegated tokens carry no principal uuid (hard cut:
// `delegated_sub` + validated `iss` only); the validated `iss` pins the
// remote_application because an issuer belongs to exactly one. Unknown or
// disabled remote_applications fail closed as invalid subjects.
func (s *Service) TouchTenantSubjectForIssuer(ctx context.Context, issuer, subject string) (*TenantSubject, error) {
	if err := s.requirePG(); err != nil {
		return nil, err
	}
	issuer = strings.TrimSpace(issuer)
	if issuer == "" {
		return nil, ErrInvalidTenantSubject
	}
	ra, err := s.GetRemoteApplication(ctx, issuer)
	if err != nil {
		if errors.Is(err, ErrRemoteApplicationNotFound) {
			return nil, ErrInvalidTenantSubject
		}
		return nil, err
	}
	if !ra.Enabled {
		return nil, ErrInvalidTenantSubject
	}
	return s.TouchTenantSubject(ctx, ra.ID, issuer, subject)
}

// TouchTenantSubject records that a remote_application accepted issuer+subject.
// The row is idempotent and updates last_seen_at on repeat use.
//
// appID is the SERVER-RESOLVED remote_application uuid (e.g. from
// TouchTenantSubjectForIssuer's issuer resolution). It is never read from a
// token claim — delegated tokens do not carry a principal uuid.
func (s *Service) TouchTenantSubject(ctx context.Context, appID, issuer, subject string) (*TenantSubject, error) {
	if err := s.requirePG(); err != nil {
		return nil, err
	}
	appID = strings.TrimSpace(appID)
	issuer = strings.TrimSpace(issuer)
	subject = strings.TrimSpace(subject)
	if appID == "" || issuer == "" || subject == "" {
		return nil, ErrInvalidTenantSubject
	}

	row, err := s.q.TenantSubjectTouch(ctx, db.TenantSubjectTouchParams{RemoteApplicationID: appID, Issuer: issuer, Subject: subject})
	if err != nil {
		// A uuid that points at no remote_application (FK 23503) or is malformed
		// (22P02) is an invalid credential, not an internal failure.
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && (pgErr.Code == "23503" || pgErr.Code == "22P02") {
			return nil, ErrInvalidTenantSubject
		}
		return nil, err
	}
	return &TenantSubject{ID: row.ID, RemoteApplicationID: row.RemoteApplicationID, Issuer: row.Issuer, Subject: row.Subject, CreatedAt: row.CreatedAt, LastSeenAt: row.LastSeenAt}, nil
}
