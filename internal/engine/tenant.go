package engine

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/open-rails/authkit/auth"
	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/internal/config"
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
	return s.ownedTenant(owner, claim)
}

// ownedTenant is credentialTenant's check of owner, the account's tenant as
// read; "" is no live account (pgx.ErrNoRows).
func (s *Engine) ownedTenant(owner, claim string) (iam.TenantID, error) {
	if owner == "" {
		return iam.TenantID{}, pgx.ErrNoRows
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
	return tenantRow(s.q.TenantByID(ctx, id.String()))
}

// CreateTenant is idempotent for the same ID and name; the same ID under
// another name is iam.ErrTenantConflict.
func (s *Engine) CreateTenant(ctx context.Context, tenant iam.Tenant) error {
	if tenant.ID.IsZero() {
		return iam.ErrTenantRequired
	}
	slug := iam.NormalizeTenantSlug(tenant.Slug)
	if err := iam.ValidateTenantSlug(slug); err != nil {
		return err
	}
	if err := s.requirePG(); err != nil {
		return err
	}
	err := s.withAuthorityMutation(ctx, iam.SystemIdentity(), func(st *permissionGroupStore) error {
		row, err := db.New(st.q).TenantCreate(ctx, db.TenantCreateParams{ID: tenant.ID.String(), Slug: slug})
		if err != nil {
			return err
		}
		if row.Slug != slug {
			return iam.ErrTenantConflict
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
	return tenantNameError(err)
}

// RenameTenant gives a tenant a new name. Under Tenants.FormerNames the old
// name forwards to it and blocks other claims; a name the tenant held before
// is taken back.
func (s *Engine) RenameTenant(ctx context.Context, id iam.TenantID, slug string) (iam.Tenant, error) {
	if id.IsZero() {
		return iam.Tenant{}, iam.ErrTenantRequired
	}
	slug = iam.NormalizeTenantSlug(slug)
	if err := iam.ValidateTenantSlug(slug); err != nil {
		return iam.Tenant{}, err
	}
	if err := s.requirePG(); err != nil {
		return iam.Tenant{}, err
	}
	tx, err := s.pg.Begin(ctx)
	if err != nil {
		return iam.Tenant{}, err
	}
	defer tx.Rollback(ctx)
	q := db.New(tx)
	current, err := q.LockTenantForRename(ctx, id.String())
	if err != nil || current.Slug == slug {
		return tenantRow(current, err)
	}
	renamed, err := q.RenameTenant(ctx, db.RenameTenantParams{ID: id.String(), Slug: slug})
	if err != nil {
		return iam.Tenant{}, tenantNameError(err)
	}
	if policy := s.cfg.Tenants.FormerNames; policy.Mode != config.NameRetentionImmediate {
		err = q.InsertTenantSlugAlias(ctx, db.InsertTenantSlugAliasParams{
			Slug: current.Slug, TenantID: id.String(),
			Forever:          policy.Mode == config.NameRetentionForever,
			RetentionSeconds: policy.Duration.Seconds(),
		})
		if err != nil {
			return iam.Tenant{}, err
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return iam.Tenant{}, err
	}
	return tenantRow(renamed, nil)
}

// ResolveTenant finds the tenant a live name or an unexpired former name
// belongs to. The returned Slug is its current name.
func (s *Engine) ResolveTenant(ctx context.Context, slug string) (iam.Tenant, error) {
	slug = iam.NormalizeTenantSlug(slug)
	if err := iam.ValidateTenantSlug(slug); err != nil {
		return iam.Tenant{}, iam.ErrTenantNotFound
	}
	if err := s.requirePG(); err != nil {
		return iam.Tenant{}, err
	}
	return tenantRow(s.q.TenantBySlugOrAlias(ctx, slug))
}

func tenantRow(row db.Tenant, err error) (iam.Tenant, error) {
	if errors.Is(err, pgx.ErrNoRows) {
		return iam.Tenant{}, iam.ErrTenantNotFound
	}
	if err != nil {
		return iam.Tenant{}, err
	}
	id, err := iam.ParseTenantID(row.ID)
	if err != nil {
		return iam.Tenant{}, err
	}
	return iam.Tenant{ID: id, Slug: row.Slug, SlugChangedAt: row.SlugChangedAt, CreatedAt: row.CreatedAt}, nil
}

// tenantNameError maps the live-name index and the former-name guard to one
// refusal.
func tenantNameError(err error) error {
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) && pgErr.Code == "23505" &&
		(pgErr.ConstraintName == "tenants_slug_key" || pgErr.ConstraintName == "tenant_slug_aliases_pkey") {
		return fmt.Errorf("%w: %w", iam.ErrTenantNameTaken, err)
	}
	return err
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
		account, usable, live, err := accountLive(ctx, s.pg, cl.Subject, iam.SessionRef{SessionID: cl.SessionID, DeviceKeyID: cl.DeviceKeyID})
		if err != nil {
			return iam.TenantActor{}, err
		}
		owner, err := s.ownedTenant(account, cl.TenantID)
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
	if !isUUID(state.ID()) || malformedSession(session) {
		return iam.TenantActor{}, auth.ErrUnauthenticated
	}
	owner, usable, signedIn, err := accountLive(ctx, s.pg, state.ID(), session)
	if err != nil {
		return iam.TenantActor{}, err
	}
	if !usable || !signedIn {
		return iam.TenantActor{}, auth.ErrUnauthenticated
	}
	if owner == "" {
		return iam.TenantActor{}, pgx.ErrNoRows
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
