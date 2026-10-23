package engine

import (
	"context"
	"errors"
	"slices"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/jackc/pgx/v5"
	"github.com/open-rails/authkit/auth"
	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/internal/apikey"
	"github.com/open-rails/authkit/internal/authflow"
	"github.com/open-rails/authkit/internal/db"
	"github.com/open-rails/authkit/internal/errmodel"
	"github.com/open-rails/authkit/internal/ident"
	"github.com/open-rails/authkit/internal/ops"
	"github.com/open-rails/authkit/verify"
)

const personalTokenMarker = "pat_"

var errPersonalTokenFresh = errors.New("personal token management requires recent authentication")

// Personal tokens reuse the opaque secret codec with a distinct fixed marker.
// Organization-key routing runs first, so a branded pat_st_ key stays a key.
func mintPersonalToken() (apikey.Minted, error) {
	m, err := apikey.Mint("")
	m.Token = personalTokenMarker + strings.TrimPrefix(m.Token, apikey.Marker(""))
	return m, err
}

func parsePersonalToken(token string) (string, string, bool) {
	rest, ok := strings.CutPrefix(strings.TrimSpace(token), personalTokenMarker)
	if !ok {
		return "", "", false
	}
	return apikey.Parse("", apikey.Marker("")+rest)
}

func (s *Engine) personalPermission(raw string) bool {
	p := ident.Perm(raw)
	return !strings.Contains(raw, "*") && s.KnownPermission(p) &&
		!strings.Contains(raw, ":credentials:") && !s.groupSchemaOrDefault().RequiresMFA([]string{raw})
}

// personalTokenManager requires an actual live interactive session, including
// its tenant binding. A PAT cannot turn itself into another credential.
func (s *Engine) personalTokenManager(ctx context.Context, st *permissionGroupStore, who auth.Identity, fresh bool) (string, error) {
	if !s.cfg.PersonalAccessTokens.Enabled {
		return "", errmodel.E(errmodel.CodeForbidden)
	}
	state := stateOf(who)
	session, _ := state.Session()
	if !state.IsUser() || session.SessionID == "" || session.DeviceKeyID != "" || state.Group() != "" {
		return "", iam.ErrInsufficientAuthority
	}
	userID := state.ID()
	if err := s.requireTenantUser(ctx, db.New(st.q), userID); err != nil {
		return "", err
	}
	live, signedIn, err := userLive(ctx, st.q, userID, session)
	if err != nil {
		return "", err
	}
	if !live || !signedIn {
		return "", iam.ErrSessionRevoked
	}
	if fresh {
		q := db.New(st.q)
		proof, err := q.SessionFreshSinceForUpdate(ctx, db.SessionFreshSinceForUpdateParams{UserID: userID, SessionID: session.SessionID, Issuer: s.cfg.Token.Issuer})
		if errors.Is(err, pgx.ErrNoRows) {
			return "", iam.ErrSessionRevoked
		}
		if err != nil {
			return "", err
		}
		mfa, err := s.recoveryEnrollment(ctx, q, userID)
		if err != nil {
			return "", err
		}
		at, methods, _ := sessionFreshness(proof.FreshSince, proof.AuthMethods, proof.MfaAuthenticatedAt).AssuranceClaims(mfa)
		if !authflow.RecentSignIn(time.Unix(at, 0), methods, mfa, s.nowTime()) {
			return "", errPersonalTokenFresh
		}
	}
	return userID, nil
}

func (s *Engine) CreatePersonalAccessToken(ctx context.Context, who auth.Identity, in iam.NewPersonalAccessToken, opts ...ops.Option) (iam.PersonalAccessTokenCreated, error) {
	var out iam.PersonalAccessTokenCreated
	if err := noOptions("CreatePersonalAccessToken", opts); err != nil {
		return out, err
	}
	name := strings.TrimSpace(in.Name)
	if name == "" || utf8.RuneCountInString(name) > 128 || len(in.Permissions) == 0 || len(in.Permissions) > 100 {
		return out, errmodel.E(errmodel.CodeInvalidRequest)
	}
	permissions := ident.Strings(in.Permissions)
	slices.Sort(permissions)
	permissions = slices.Compact(permissions)
	for _, p := range permissions {
		if !s.personalPermission(p) {
			return out, errmodel.E(errmodel.CodeInvalidRequest, errmodel.WithParam("permissions"))
		}
	}
	now := s.nowTime()
	expires := now.Add(s.cfg.PersonalAccessTokens.DefaultTTL)
	if in.ExpiresAt != nil {
		expires = in.ExpiresAt.UTC()
	}
	if !expires.After(now) || expires.After(now.Add(s.cfg.PersonalAccessTokens.MaxTTL)) {
		return out, errmodel.E(errmodel.CodeInvalidRequest, errmodel.WithParam("expires_at"))
	}
	err := s.withAuthorityMutation(ctx, who, func(st *permissionGroupStore) error {
		owner, err := s.personalTokenManager(ctx, st, who, true)
		if err != nil {
			return err
		}
		group, err := s.resolveGroup(ctx, st, iam.GroupByID(in.GroupID))
		if err != nil {
			return err
		}
		authority, err := s.identityAuthority(ctx, st, who, group)
		if err != nil {
			return err
		}
		if err := authority.requireCover(permissions); err != nil {
			return err
		}
		for range 5 {
			m, err := mintPersonalToken()
			if err != nil {
				return err
			}
			row, err := db.New(st.q).PersonalTokenInsert(ctx, db.PersonalTokenInsertParams{OwnerUserID: owner, GroupID: group.ID, Issuer: s.cfg.Token.Issuer,
				LookupID: m.LookupID, SecretHash: m.SecretHash, Name: name, Permissions: permissions, ExpiresAt: expires})
			if errors.Is(err, pgx.ErrNoRows) {
				continue
			}
			if err != nil {
				return err
			}
			out = iam.PersonalAccessTokenCreated{Token: iam.PersonalAccessToken{ID: row.ID, OwnerUserID: owner, GroupID: group.ID, Name: name,
				Permissions: ident.Perms(permissions), CreatedAt: row.CreatedAt, ExpiresAt: expires}, Secret: m.Token}
			return nil
		}
		return errors.New("personal token lookup collision")
	})
	if errors.Is(err, errPersonalTokenFresh) {
		err = s.StepUpRequired(ctx, stateOf(who).ID())
	}
	return out, err
}

func (s *Engine) ListPersonalAccessTokens(ctx context.Context, who auth.Identity, page iam.PageRequest) (iam.ListPage[iam.PersonalAccessToken], error) {
	out := iam.ListPage[iam.PersonalAccessToken]{Items: []iam.PersonalAccessToken{}}
	after, err := idCursor(page)
	if err != nil {
		return out, err
	}
	err = s.withAuthorityMutation(ctx, who, func(st *permissionGroupStore) error {
		owner, err := s.personalTokenManager(ctx, st, who, false)
		if err != nil {
			return err
		}
		rows, err := db.New(st.q).PersonalTokensByOwner(ctx, db.PersonalTokensByOwnerParams{OwnerUserID: owner, Issuer: s.cfg.Token.Issuer, After: after, PageLimit: int64(page.PageLimit() + 1)})
		if err != nil {
			return err
		}
		items := make([]iam.PersonalAccessToken, 0, len(rows))
		for _, row := range rows {
			items = append(items, iam.PersonalAccessToken{ID: row.ID, OwnerUserID: row.OwnerUserID, GroupID: row.PermissionGroupID, Name: row.Name,
				Permissions: ident.Perms(row.Permissions), CreatedAt: row.CreatedAt, LastUsedAt: row.LastUsedAt, ExpiresAt: row.ExpiresAt, RevokedAt: row.RevokedAt})
		}
		out = idPage(items, page.PageLimit(), func(token iam.PersonalAccessToken) string { return token.ID })
		return nil
	})
	return out, err
}

func (s *Engine) RevokePersonalAccessToken(ctx context.Context, who auth.Identity, id string, opts ...ops.Option) error {
	if err := noOptions("RevokePersonalAccessToken", opts); err != nil {
		return err
	}
	err := s.withAuthorityMutation(ctx, who, func(st *permissionGroupStore) error {
		owner, err := s.personalTokenManager(ctx, st, who, true)
		if err != nil {
			return err
		}
		if !isUUID(id) {
			return errmodel.E(errmodel.CodeInvalidRequest)
		}
		return db.New(st.q).PersonalTokenRevoke(ctx, db.PersonalTokenRevokeParams{ID: id, OwnerUserID: owner, Issuer: s.cfg.Token.Issuer})
	})
	if errors.Is(err, errPersonalTokenFresh) {
		return s.StepUpRequired(ctx, stateOf(who).ID())
	}
	return err
}

// Only this token's group is reachable. Current owner grants are intersected
// with concrete stored permissions every time; positive checks are not cached.
func (s *Engine) personalTokenAuthority(ctx context.Context, st *permissionGroupStore, out authority, id string, group groupTarget) (authority, error) {
	if !s.cfg.PersonalAccessTokens.Enabled || !isUUID(id) {
		return out, iam.ErrInsufficientAuthority
	}
	row, err := db.New(st.q).PersonalTokenByID(ctx, db.PersonalTokenByIDParams{ID: id, Issuer: s.cfg.Token.Issuer})
	if errors.Is(err, pgx.ErrNoRows) {
		return out, iam.ErrInsufficientAuthority
	}
	if err != nil {
		return out, err
	}
	if row.PermissionGroupID != group.ID {
		return out, nil
	}
	tenant, err := iam.ParseTenantID(row.TenantID)
	if err != nil {
		return out, err
	}
	owner := iam.InTenant(iam.UserIdentity(row.OwnerUserID), tenant)
	current, err := s.userAuthority(ctx, st, authority{who: owner}, row.OwnerUserID, iam.SessionRef{}, group)
	if err != nil {
		return out, err
	}
	out.credentialGroup = group.ID
	for _, p := range row.Permissions {
		if s.personalPermission(p) && current.covers(ident.Perm(p)) {
			out.grants = append(out.grants, p)
		}
	}
	return out, nil
}

func (s *Engine) ResolvePersonalAccessToken(ctx context.Context, token string) (iam.ResolvedPersonalAccessToken, error) {
	var out iam.ResolvedPersonalAccessToken
	lookup, secret, ok := parsePersonalToken(token)
	if !ok || !s.cfg.PersonalAccessTokens.Enabled {
		return out, iam.ErrPersonalAccessTokenInvalid
	}
	if err := s.requirePG(); err != nil {
		return out, err
	}
	row, err := s.q.PersonalTokenByLookupID(ctx, db.PersonalTokenByLookupIDParams{LookupID: lookup, Issuer: s.cfg.Token.Issuer})
	if errors.Is(err, pgx.ErrNoRows) {
		return out, iam.ErrPersonalAccessTokenInvalid
	}
	if err != nil {
		return out, err
	}
	if !apikey.Matches(row.SecretHash, secret) {
		return out, iam.ErrPersonalAccessTokenInvalid
	}
	group := groupTarget{ID: row.PermissionGroupID, Persona: ident.Persona(row.Persona)}
	authority, err := s.personalTokenAuthority(ctx, s.groupStore(), authority{}, row.ID, group)
	if errors.Is(err, iam.ErrInsufficientAuthority) || errors.Is(err, iam.ErrTwoFAEnrollmentRequired) {
		return out, iam.ErrPersonalAccessTokenInvalid
	}
	if err != nil {
		return out, err
	}
	tenant, err := iam.ParseTenantID(row.TenantID)
	if err != nil {
		return out, err
	}
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = s.q.PersonalTokenTouch(ctx, row.ID)
	}()
	return iam.ResolvedPersonalAccessToken{ID: row.ID, OwnerUserID: row.OwnerUserID, TenantID: tenant,
		Group: iam.Group{ID: group.ID, Persona: group.Persona, CreatedAt: row.GroupCreatedAt}, Issuer: s.cfg.Token.Issuer, Permissions: ident.Perms(authority.grants)}, nil
}

func (s *Engine) personalTokenClaims(ctx context.Context, token string) (verify.Claims, error) {
	p, err := s.ResolvePersonalAccessToken(ctx, token)
	if err != nil {
		return verify.Claims{}, err
	}
	return verify.Claims{Kind: verify.TokenPersonalAccessToken, Issuer: p.Issuer, UserID: p.OwnerUserID, TenantID: p.TenantID.String(), PersonalAccessTokenID: p.ID,
		Permissions: ident.Strings(p.Permissions), Group: &verify.PermissionScope{GroupID: p.Group.ID, AuthorityIssuer: p.Issuer, Persona: p.Group.Persona}}, nil
}
