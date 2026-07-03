package authcore

import (
	"context"
	stdlog "log"
	"strings"
	"time"

	jwt "github.com/golang-jwt/jwt/v5"
	"github.com/open-rails/authkit/jwtkit"
)

// IssueAccessToken builds and signs an access token (JWT) for the given user.
// Includes core registered claims plus:
// - entitlements (authoritative short-lived snapshot)
// Extra claims in `extra` are merged into the token body (e.g., sid).
func (s *Service) IssueAccessToken(ctx context.Context, userID string, extra map[string]any) (token string, expiresAt time.Time, err error) {
	return s.issueAccessToken(ctx, userID, extra, s.cfg.Token.AccessTokenDuration)
}

func (s *Service) Issue2FAEnrollmentToken(ctx context.Context, userID string) (token string, expiresAt time.Time, err error) {
	return s.issueAccessToken(ctx, userID, map[string]any{"2fa_enrollment": true}, 10*time.Minute)
}

// reservedAccessTokenClaims are claims the verifier extracts as authoritative
// identity / authorization / assurance (see verify/verifier.go extractClaims).
// AuthKit sets these itself from authenticated state, or not at all; a
// caller-supplied `extra` value for any of them is DROPPED, never signed
// (AK2-AUTH-01). Without this, a host that forwards any request-influenced data
// into IssueAccessToken / PasswordLogin(...extra) could mint a validly-signed
// token with attacker-chosen roles/permissions/identity, which the verifier then
// trusts (verify/middleware.go even skips the DB role lookup when the token
// already carries `roles`).
//
// Intentionally NOT reserved: `sid`, `provider`, `2fa_enrollment`, and arbitrary
// host/custom claims are deliberate, caller-settable protocol/app claims set by
// AuthKit's own flows (login/OIDC/passkey/enrollment) and carry no authority the
// verifier trusts as identity. AuthKit-owned claims (iss/sub/aud/iat/exp/
// entitlements, and auth_time/amr/acr/mfa_enrolled when AuthKit sets them) are
// already protected by the owned-claim check below; they appear here too so a
// host can never inject the assurance variants AuthKit did not set.
var reservedAccessTokenClaims = map[string]struct{}{
	"roles":            {},
	"permissions":      {},
	"global_roles":     {},
	"org_roles":        {},
	"groups":           {},
	"email":            {},
	"email_verified":   {},
	"username":         {},
	"discord_username": {},
	"user_tier":        {},
	"plan":             {},
	"delegated_sub":    {},
	"attributes":       {},
	"amr":              {},
	"acr":              {},
	"auth_time":        {},
	"jti":              {},
	"mfa_enrolled":     {},
}

// issueAccessToken is the ID-only entry point: it loads + gates the live-user row
// and computes MFAStatus, then delegates to issueAccessTokenForUser. Callers that
// already hold a loaded+gated *User (and its MFAStatus) — the hot login / refresh /
// 2FA paths — should call issueAccessTokenForUser directly to avoid the re-read (#227).
func (s *Service) issueAccessToken(ctx context.Context, userID string, extra map[string]any, ttl time.Duration) (token string, expiresAt time.Time, err error) {
	// Keep the live-user gate even though profile fields no longer ride in the
	// token: banned/deleted users must not receive fresh access tokens.
	if s.pg != nil {
		u, uErr := s.getUserByID(ctx, userID)
		if uErr != nil {
			return "", time.Time{}, uErr
		}
		if u == nil {
			return "", time.Time{}, jwt.ErrTokenInvalidClaims
		}
		if err := s.ensureUserAccess(ctx, u); err != nil {
			return "", time.Time{}, err
		}
		var mfa *MFAStatus
		if status, mfaErr := s.MFAStatus(ctx, userID); mfaErr == nil {
			mfa = &status
		}
		return s.issueAccessTokenForUser(ctx, u, mfa, extra, ttl)
	}
	// Verify-only / pg-less Service: no live-user gate, no MFA lookup — mint from
	// the userID alone (matches the historical s.pg == nil behavior). The synthetic
	// row carries only the ID; issueAccessTokenForUser reads no other user field and
	// its sid/freshness + mfa branches are already guarded by s.pg != nil / mfa != nil.
	return s.issueAccessTokenForUser(ctx, &User{ID: userID}, nil, extra, ttl)
}

// issueAccessTokenForUser mints an access token for an ALREADY-LOADED, ALREADY-GATED
// user (#227). It SKIPS the getUserByID + ensureUserAccess "live-user gate" that
// issueAccessToken performs — the caller has already loaded the row and rejected
// banned/deleted/reserved users — and reuses a precomputed MFAStatus for the
// mfa_enrolled claim instead of recomputing it. Pass mfa == nil to omit mfa_enrolled
// (matches the swallow-on-error / absent-when-not-satisfied behavior of the ID-only
// path). u must be non-nil.
func (s *Service) issueAccessTokenForUser(ctx context.Context, u *User, mfa *MFAStatus, extra map[string]any, ttl time.Duration) (token string, expiresAt time.Time, err error) {
	userID := u.ID
	base := jwtkit.BaseRegisteredClaims(userID, s.cfg.Token.IssuedAudiences, ttl)
	expiresAt = base.ExpiresAt.Time
	// Group/role authority is no longer carried as a token claim: the legacy
	// `global_roles`/`roles` plane was hard-cut in favor of the permission-group
	// RBAC engine (#111) — group role assignments + `<persona>:<resource>:<action>`
	// perms resolved at request time from the DB (svc.Can), not snapshotted into
	// the access token.
	var ents []string
	if s.entitlements != nil {
		var entErr error
		ents, entErr = s.entitlements.ListEntitlements(ctx, userID)
		if entErr != nil {
			// Deliberate availability-over-consistency: a failing entitlements
			// provider must not block login, but it must be LOUD — the user is
			// getting a token without entitlement claims (no premium access)
			// until the next refresh.
			stdlog.Printf("authkit: error: entitlements provider failed during access-token issuance for user %s; token issued WITHOUT entitlement claims: %v", userID, entErr)
			ents = nil
		}
	}

	claims := map[string]any{
		"iss":          s.cfg.Token.Issuer,
		"sub":          base.Subject,
		"aud":          base.Audience,
		"iat":          base.IssuedAt.Time.Unix(),
		"exp":          base.ExpiresAt.Time.Unix(),
		"entitlements": ents,
	}
	if sid, ok := extra["sid"].(string); ok && strings.TrimSpace(sid) != "" && s.pg != nil {
		if freshness, freshErr := s.SessionFreshness(ctx, userID, sid, time.Now()); freshErr == nil {
			authTime, amr, acr := freshness.AssuranceClaims()
			claims["auth_time"] = authTime
			claims["amr"] = amr
			claims["acr"] = acr
		}
	}
	// mfa_enrolled lets the stateless Sensitive() gate require 2FA from users who
	// have a usable second factor, without a DB call at gate time. Emitted only
	// when true (absent ⇒ false). Reflects state at mint, so it's at most one
	// token-TTL stale after enroll/disable.
	if mfa != nil && mfa.Satisfied {
		claims["mfa_enrolled"] = true
	}
	// Caller-supplied claims fill gaps but never override an AuthKit-owned claim
	// (sub/iss/aud/iat/exp/entitlements always; auth_time/amr/acr/mfa_enrolled when
	// set) and never populate a reserved authority/identity/assurance claim the
	// verifier trusts (AK2-AUTH-01). This prevents a host from forging identity,
	// authorization, expiry, or assurance via extra, while still allowing custom
	// claims and the deliberate protocol claims (sid/provider/2fa_enrollment).
	for k, v := range extra {
		if _, owned := claims[k]; owned {
			continue
		}
		if _, reserved := reservedAccessTokenClaims[k]; reserved {
			// Surface the misuse (key only — values may be PII): AuthKit's own
			// flows never put these in extra, so a hit means a host is trying to
			// set authority/identity it does not control.
			safeUserID := strings.ReplaceAll(userID, "\n", "")
			safeUserID = strings.ReplaceAll(safeUserID, "\r", "")
			stdlog.Printf("authkit: warning: dropping reserved claim %q from caller-supplied extra during access-token issuance for user %s", k, safeUserID)
			continue
		}
		claims[k] = v
	}
	if s.keys.Active == nil {
		return "", time.Time{}, ErrMissingSigner // #87: verify-only Service cannot mint
	}
	tok, err := jwtkit.SignWithType(ctx, s.keys.Active, claims, jwtkit.AccessTokenType, true)
	return tok, expiresAt, err
}
