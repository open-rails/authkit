package engine

import (
	"context"
	"errors"
	stdlog "log"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/internal/authflow"
	"github.com/open-rails/authkit/internal/db"
	"github.com/open-rails/authkit/internal/errmodel"
	"github.com/open-rails/authkit/internal/ident"
	"github.com/open-rails/authkit/internal/jose"
	"github.com/open-rails/authkit/internal/ops"
)

// MintAccessToken mints an access token for a live account outside any login
// flow; a host operation. o.Claims naming one of AuthKit's own claims is
// invalid_request (param claims.<name>); o.SessionID becomes sid.
func (s *Engine) MintAccessToken(ctx context.Context, userID string, o iam.AccessTokenOptions, opts ...ops.Option) (iam.Token, error) {
	if err := noOptions("MintAccessToken", opts); err != nil {
		return iam.Token{}, err
	}
	for k := range o.Claims {
		if authkitClaims[k] {
			return iam.Token{}, errmodel.E(errmodel.CodeInvalidRequest, errmodel.WithParam("claims."+k))
		}
	}
	userID = strings.TrimSpace(userID)
	if !isUUID(userID) {
		return iam.Token{}, iam.ErrUserNotFound
	}
	extra := make(map[string]any, len(o.Claims)+1)
	for k, v := range o.Claims {
		extra[k] = v
	}
	if sid := strings.TrimSpace(o.SessionID); sid != "" {
		extra["sid"] = sid
	}
	ttl := o.TTL
	if ttl <= 0 {
		ttl = s.cfg.Token.AccessTokenDuration
	}
	token, exp, err := s.mintAccessToken(ctx, userID, extra, ttl)
	if errors.Is(err, pgx.ErrNoRows) {
		return iam.Token{}, iam.ErrUserNotFound
	}
	return iam.Token{Value: token, ExpiresAt: exp}, err
}

// MintSessionAccessToken re-mints the access token of the caller's own
// session (step-up and provider-link responses).
func (s *Engine) MintSessionAccessToken(ctx context.Context, userID, sessionID string) (string, time.Time, error) {
	return s.mintAccessToken(ctx, userID, map[string]any{"sid": sessionID}, s.cfg.Token.AccessTokenDuration)
}

// authkitClaims are the claim names AuthKit's tokens use (docs/stability.md
// lists them per typ), plus the profile claims verify reads from an access
// token. A host's MintAccessToken claims may not name one: AuthKit sets these
// from authenticated state or not at all, so a host forwarding
// request-influenced data can never forge identity, session or assurance.
var authkitClaims = map[string]bool{
	"iss": true, "sub": true, "aud": true, "iat": true, "nbf": true, "exp": true, "jti": true,
	"sid": true, "device_key_id": true, "auth_time": true, "amr": true, "acr": true, "mfa_enrolled": true,
	"root_role": true, "entitlements": true, "2fa_enrollment": true, "provider": true,
	"delegated_sub": true, "permissions": true, "attributes": true, "cnf": true, "token_use": true,
	"email": true, "email_verified": true, "username": true,
}

// mintAccessToken is the ID-only entry point: it loads + gates the live-user row
// and computes MFAStatus, then delegates to mintAccessTokenForUser. Callers that
// already hold a loaded+gated *User (and its MFAStatus) — the hot login / refresh /
// 2FA paths — should call mintAccessTokenForUser directly to avoid the re-read (#227).
func (s *Engine) mintAccessToken(ctx context.Context, userID string, extra map[string]any, ttl time.Duration) (token string, expiresAt time.Time, err error) {
	// Keep the live-user gate even though profile fields no longer ride in the
	// token: banned/deleted users must not receive fresh access tokens.
	if s.pg != nil {
		u, uErr := s.getUserByID(ctx, userID)
		if uErr != nil {
			return "", time.Time{}, uErr
		}
		if u == nil {
			return "", time.Time{}, iam.ErrUserNotFound
		}
		if err := s.ensureUserAccess(ctx, u); err != nil {
			return "", time.Time{}, err
		}
		var mfa *authflow.MFAStatus
		if status, mfaErr := s.mfaStatus(ctx, userID); mfaErr == nil {
			mfa = &status
		}
		return s.mintAccessTokenForUser(ctx, s.q, u, mfa, extra, ttl)
	}
	// Verify-only / pg-less engine: no live-user gate, no MFA lookup — mint from
	// the userID alone (matches the historical s.pg == nil behavior). The synthetic
	// row carries only the ID; mintAccessTokenForUser reads no other user field and
	// its sid/freshness + mfa branches are already guarded by s.pg != nil / mfa != nil.
	return s.mintAccessTokenForUser(ctx, s.q, &db.User{ID: userID}, nil, extra, ttl)
}

// mintAccessTokenForUser mints an access token for an ALREADY-LOADED, ALREADY-GATED
// user (#227). It SKIPS the getUserByID + ensureUserAccess "live-user gate" that
// mintAccessToken performs — the caller has already loaded the row and rejected
// banned/deleted/reserved users — and reuses a precomputed MFAStatus for the
// mfa_enrolled claim instead of recomputing it. Pass mfa == nil to omit mfa_enrolled
// (matches the swallow-on-error / absent-when-not-satisfied behavior of the ID-only
// path). u must be non-nil.
func (s *Engine) mintAccessTokenForUser(ctx context.Context, q *db.Queries, u *db.User, mfa *authflow.MFAStatus, extra map[string]any, ttl time.Duration) (token string, expiresAt time.Time, err error) {
	return s.mintAccessTokenForUserWithAssurance(ctx, q, u, mfa, extra, ttl, nil)
}

type accessTokenAssurance struct {
	JTI         string
	AuthTime    int64
	AMR         []string
	ACR         string
	DeviceKeyID string
}

func (s *Engine) mintAccessTokenForUserWithAssurance(ctx context.Context, q *db.Queries, u *db.User, mfa *authflow.MFAStatus, extra map[string]any, ttl time.Duration, assurance *accessTokenAssurance) (token string, expiresAt time.Time, err error) {
	userID := u.ID
	now := time.Now()
	expiresAt = now.Add(ttl)
	// Authority is never a token claim: permissions resolve live (Can). The
	// root role rides along for display only (Claims.RootRole).
	var ents []string
	if len(s.cfg.Token.EntitlementAllowlist) > 0 && s.entitlements != nil {
		m, entErr := s.entitlements(ctx, []string{userID})
		if entErr != nil {
			// Deliberate availability-over-consistency: a failing entitlements
			// provider must not block login, but it must be LOUD — the user is
			// getting a token without entitlement claims (no premium access)
			// until the next refresh.
			stdlog.Printf("authkit: error: entitlements provider failed during access-token issuance for user %s; token issued WITHOUT entitlement claims: %v", userID, entErr)
		} else {
			ents = selectedTokenEntitlements(s.cfg.Token.EntitlementAllowlist, m[userID])
		}
	}

	claims := map[string]any{
		"iss": s.cfg.Token.Issuer,
		"sub": userID,
		"aud": s.cfg.Token.IssuedAudiences,
		"iat": now.Unix(),
		"exp": expiresAt.Unix(),
	}
	if len(ents) > 0 {
		claims["entitlements"] = ents
	}
	if role := s.displayRootRole(ctx, q, userID); role != "" {
		claims["root_role"] = role
	}
	if assurance != nil {
		if assurance.JTI != "" {
			claims["jti"] = assurance.JTI
		}
		claims["auth_time"] = assurance.AuthTime
		claims["amr"] = append([]string(nil), assurance.AMR...)
		claims["acr"] = assurance.ACR
		if assurance.DeviceKeyID != "" {
			claims["device_key_id"] = assurance.DeviceKeyID
		}
	} else if sid, ok := extra["sid"].(string); ok && strings.TrimSpace(sid) != "" && s.pg != nil {
		if freshness, freshErr := s.SessionFreshness(ctx, userID, sid, time.Now()); freshErr == nil {
			// An unknown MFA state counts as enrolled: the token is then fresh
			// only as of the session's last second factor.
			authTime, amr, acr := freshness.AssuranceClaims(mfa == nil || mfa.Satisfied)
			claims["auth_time"] = authTime
			claims["amr"] = amr
			claims["acr"] = acr
		}
	}
	// mfa_enrolled lets the stateless Sensitive() gate require 2FA from users who
	// have a usable second factor, without a DB call at gate time. Emitted only
	// when true (absent ⇒ false). Reflects state at mint, so it's at most one
	// token-TTL stale after enroll/disable.
	amr, _ := claims["amr"].([]string)
	if mfa != nil && mfa.Satisfied || hasAuthMethod(amr, "swk") && hasAuthMethod(amr, "mfa") {
		claims["mfa_enrolled"] = true
	}
	// extra fills gaps and never overrides a claim set above. AuthKit's flows
	// put only their protocol claims (sid, provider, 2fa_enrollment) in it,
	// and MintAccessToken refuses host claims named like AuthKit's.
	for k, v := range extra {
		if _, owned := claims[k]; !owned {
			claims[k] = v
		}
	}
	signer := s.keys.ActiveSigner()
	if signer == nil {
		return "", time.Time{}, iam.ErrSigningNotConfigured // #87: a verify-only engine cannot mint
	}
	tok, err := jose.Sign(ctx, signer, jose.AccessTokenType, claims)
	return tok, expiresAt, err
}

// displayRootRole is the user's root-group role for the display-only
// root_role claim, read through q: the caller's transaction when it holds
// one, so a mint never waits on a second connection. "" without one or when
// it cannot be read: a token is never refused for want of a display hint.
func (s *Engine) displayRootRole(ctx context.Context, q *db.Queries, userID string) string {
	rootID, _ := s.rootGroupID.Load().(string)
	if q == nil || rootID == "" {
		return ""
	}
	rows, err := q.GroupRolesForSubjects(ctx, db.GroupRolesForSubjectsParams{GroupID: rootID, UserIds: []string{userID}})
	if err != nil || len(rows) != 1 {
		return ""
	}
	role := ident.RoleText(rows[0].Role)
	if _, ok := s.groupSchemaOrDefault().Role(iam.RootPersona(), role); !ok {
		return ""
	}
	return role.String()
}

// mintDeviceKeyAccessToken is AuthKit's refreshless native-client issuer. The
// assurance claims are server-owned, not passed through MintAccessToken's host
// extras, so callers cannot forge an authentication method. amr is what the
// ceremony proved; it passes the same session MFA gate as every login.
func (s *Engine) mintDeviceKeyAccessToken(ctx context.Context, userID, deviceKeyID string, amr []string) (string, time.Time, error) {
	u, err := s.getUserByID(ctx, userID)
	if err != nil {
		return "", time.Time{}, err
	}
	if err := s.ensureUserAccess(ctx, u); err != nil {
		return "", time.Time{}, err
	}
	status, mfaErr := s.mfaStatus(ctx, userID)
	if err := s.requireSessionMFAStateOn(ctx, s.pg, userID, amr, status, mfaErr); err != nil {
		return "", time.Time{}, err
	}
	var mfa *authflow.MFAStatus
	if mfaErr == nil {
		mfa = &status
	}
	now := time.Now().UTC()
	acr := iam.AssuranceLevelPassword
	if hasAuthMethod(amr, "mfa") {
		acr = iam.AssuranceLevelMFA
	}
	return s.mintAccessTokenForUserWithAssurance(ctx, s.q, u, mfa, nil, s.cfg.Token.AccessTokenDuration, &accessTokenAssurance{
		AuthTime:    now.Unix(),
		AMR:         amr,
		ACR:         acr,
		DeviceKeyID: deviceKeyID,
	})
}
