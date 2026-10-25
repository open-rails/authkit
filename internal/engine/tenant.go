package engine

import (
	"context"
	"errors"
	"slices"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/open-rails/authkit/auth"
	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/internal/db"
	"github.com/open-rails/authkit/internal/tenancy"
	"github.com/open-rails/authkit/verify"
)

// WithTenant is used only by the native tenant view and trusted HTTP dispatch.
// It selects a target; it never establishes a caller's authority over it.
func WithTenant(ctx context.Context, id iam.TenantID) context.Context {
	return tenancy.With(ctx, id)
}

func (s *Engine) tenantID(ctx context.Context) (iam.TenantID, error) {
	if id, ok := tenancy.From(ctx); ok {
		if id.IsZero() {
			return id, iam.ErrTenantRequired
		}
		return id, nil
	}
	if s.cfg.DefaultTenantID.IsZero() {
		return iam.TenantID{}, iam.ErrTenantRequired
	}
	return s.cfg.DefaultTenantID, nil
}

func (s *Engine) tenantKey(ctx context.Context) string {
	id, _ := s.tenantID(ctx)
	return id.String()
}

// AccountScope is the fixed account directory selected by trusted dispatch.
func (s *Engine) AccountScope(ctx context.Context) (iam.GroupRef, error) {
	id, err := s.tenantID(ctx)
	if err != nil {
		return iam.GroupRef{}, err
	}
	return iam.GroupByID(id.String()), nil
}

// requireTenantUser is a target lookup, never a source-authority lookup. Once
// checked, immutable account ownership makes ID-only child-row reads safe.
func (s *Engine) requireTenantUser(ctx context.Context, q *db.Queries, userID string) error {
	if _, err := s.tenantID(ctx); err != nil {
		return err
	}
	if !isUUID(userID) {
		return iam.ErrUserNotFound
	}
	if err := s.requirePG(); err != nil {
		return err
	}
	_, err := q.TenantUserByID(ctx, db.TenantUserByIDParams{TenantID: s.tenantKey(ctx), ID: userID})
	if errors.Is(err, pgx.ErrNoRows) {
		return iam.ErrUserNotFound
	}
	return err
}

// credentialTenant checks source ownership independently of a request's
// target. Only the explicit deployment default may adopt a claimless token.
func (s *Engine) credentialTenant(ctx context.Context, q *db.Queries, userID, claim string) (iam.TenantID, error) {
	owner, err := q.AccountTenant(ctx, userID)
	if err != nil {
		return iam.TenantID{}, err
	}
	actual, err := iam.ParseTenantID(owner)
	if err != nil {
		return iam.TenantID{}, err
	}
	claimed := s.cfg.DefaultTenantID
	if claim != "" {
		claimed, err = iam.ParseTenantID(claim)
		if err != nil {
			return iam.TenantID{}, iam.ErrTenantMismatch
		}
	}
	if claimed.IsZero() || claimed != actual {
		return iam.TenantID{}, iam.ErrTenantMismatch
	}
	return actual, nil
}

func (s *Engine) Tenant(ctx context.Context, id iam.TenantID) (iam.Tenant, error) {
	if id.IsZero() {
		return iam.Tenant{}, iam.ErrTenantRequired
	}
	if err := s.requirePG(); err != nil {
		return iam.Tenant{}, err
	}
	row, err := s.q.TenantByID(ctx, id.String())
	if errors.Is(err, pgx.ErrNoRows) {
		return iam.Tenant{}, iam.ErrTenantNotFound
	}
	if err != nil {
		return iam.Tenant{}, err
	}
	return iam.Tenant{ID: id, CreatedAt: row.CreatedAt}, nil
}

func (s *Engine) CreateTenant(ctx context.Context, tenant iam.Tenant) error {
	if tenant.ID.IsZero() {
		return iam.ErrTenantRequired
	}
	if err := s.requirePG(); err != nil {
		return err
	}
	return s.withAuthorityMutation(ctx, iam.SystemIdentity(), func(st *permissionGroupStore) error {
		if _, err := db.New(st.q).TenantCreate(ctx, tenant.ID.String()); err != nil {
			return err
		}
		if err := bindNotificationScope(ctx, st.q, s.cfg.Database, s.cfg.Notifications, tenant.ID, true); err != nil {
			return err
		}
		g, err := st.groupByID(ctx, tenant.ID.String())
		if err == nil {
			if g.Persona != iam.TenantPersona() || g.TenantID != tenant.ID {
				return iam.ErrGroupConflict
			}
			return nil
		}
		if !errors.Is(err, iam.ErrGroupNotFound) {
			return err
		}
		_, err = st.CreateGroup(ctx, tenant.ID.String(), iam.TenantPersona(), tenant.ID)
		return err
	})
}

// ResolveTenantActor resolves the live source account, independently of the
// request's target tenant and without creating a target account for operators.
func (s *Engine) ResolveTenantActor(ctx context.Context, verified auth.Verified) (iam.TenantActor, error) {
	if verified == nil {
		return iam.TenantActor{}, auth.ErrUnauthenticated
	}
	if err := s.requirePG(); err != nil {
		return iam.TenantActor{}, err
	}
	if resource, ok := verified.(resourceVerified); ok && resource.access.Application == nil {
		cl := resource.access.Claims
		if cl.Kind != verify.TokenUser || cl.Issuer != s.cfg.Token.Issuer {
			return iam.TenantActor{}, auth.ErrForbidden
		}
		if !cl.ValidUntil.IsZero() && time.Now().After(cl.ValidUntil) {
			return iam.TenantActor{}, errors.Join(auth.ErrUnauthenticated, auth.ErrExpired, iam.ErrTokenExpired)
		}
		owner, err := s.credentialTenant(ctx, s.q, cl.Subject, cl.TenantID)
		if err != nil {
			return iam.TenantActor{}, err
		}
		usable, live, err := userLive(ctx, s.pg, cl.Subject, iam.SessionRef{SessionID: cl.SessionID, DeviceKeyID: cl.DeviceKeyID})
		if err != nil {
			return iam.TenantActor{}, err
		}
		if !usable || !live {
			return iam.TenantActor{}, auth.ErrUnauthenticated
		}
		return iam.TenantActor{AccountID: cl.Subject, TenantID: owner}, nil
	}
	id := verified.Identity()
	state, ok := iam.StateOf(id)
	if !ok || !state.IsUser() || id.SubjectKind != auth.SubjectUser ||
		(id.Issuer != s.cfg.Token.Issuer && !slices.Contains(s.cfg.Token.AccountIssuers, id.Issuer)) {
		return iam.TenantActor{}, auth.ErrForbidden
	}
	if deadline := state.ValidUntil(); !deadline.IsZero() && time.Now().After(deadline) {
		return iam.TenantActor{}, errors.Join(auth.ErrUnauthenticated, auth.ErrExpired, iam.ErrTokenExpired)
	}
	if err := s.requirePG(); err != nil {
		return iam.TenantActor{}, err
	}
	session, _ := state.Session()
	usable, signedIn, err := userLive(ctx, s.pg, state.ID(), session)
	if err != nil {
		return iam.TenantActor{}, err
	}
	if !usable || !signedIn {
		return iam.TenantActor{}, auth.ErrUnauthenticated
	}
	owner, err := s.q.AccountTenant(ctx, state.ID())
	if err != nil {
		return iam.TenantActor{}, err
	}
	tenant, err := iam.ParseTenantID(owner)
	if err != nil {
		return iam.TenantActor{}, err
	}
	// Claimless legacy identities may only retain their explicitly configured
	// default directory. A target selector is never a source-tenant fallback.
	claimed := state.TenantID()
	if claimed.IsZero() {
		claimed = s.cfg.DefaultTenantID
	}
	if claimed.IsZero() || claimed != tenant {
		return iam.TenantActor{}, auth.ErrForbidden
	}
	return iam.TenantActor{AccountID: state.ID(), TenantID: tenant}, nil
}
