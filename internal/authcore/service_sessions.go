package authcore

import (
	"context"
	"crypto/sha256"
	"errors"
	stdlog "log"
	"net"
	"strings"
	"time"

	jwt "github.com/golang-jwt/jwt/v5"
	"github.com/jackc/pgx/v5"

	"github.com/open-rails/authkit/internal/db"
)

// Session represents a sanitized session view (no tokens).
type Session struct {
	ID                  string
	FamilyID            string
	CreatedAt           time.Time
	LastAuthenticatedAt *time.Time
	LastUsedAt          time.Time
	ExpiresAt           *time.Time
	RevokedAt           *time.Time
	UserAgent           *string
	IPAddr              *string
}

const SensitiveActionFreshAuthWindow = 15 * time.Minute

const (
	AssuranceLevelPassword = "urn:authkit:loa:1"
	AssuranceLevelMFA      = "urn:authkit:loa:2"
)

var ErrReauthenticationRequired = errors.New("reauth_required")

type SessionFreshness struct {
	LastAuthenticatedAt           time.Time
	TimeUntilReauthRequired       time.Duration
	ReauthRequiredForSensitiveOps bool
	AuthMethods                   []string
}

func (f SessionFreshness) AssuranceClaims() (authTime int64, amr []string, acr string) {
	amr = normalizeAuthMethods(f.AuthMethods)
	acr = AssuranceLevelPassword
	for _, method := range amr {
		if method == "otp" || method == "mfa" {
			acr = AssuranceLevelMFA
			break
		}
	}
	return f.LastAuthenticatedAt.Unix(), amr, acr
}

// IssueRefreshSession creates a session row and returns a new refresh token string.
func (s *Service) IssueRefreshSession(ctx context.Context, userID, userAgent string, ip net.IP) (sessionID, refreshToken string, expiresAt *time.Time, err error) {
	return s.IssueRefreshSessionWithAuthMethods(ctx, userID, userAgent, ip, []string{"pwd"})
}

// IssueRefreshSessionWithAuthMethods creates a refresh session and records the
// authentication methods that established it. Callers minting a session after
// MFA should pass e.g. []string{"pwd", "otp", "mfa"}.
func (s *Service) IssueRefreshSessionWithAuthMethods(ctx context.Context, userID, userAgent string, ip net.IP, authMethods []string) (sessionID, refreshToken string, expiresAt *time.Time, err error) {
	if s.pg == nil {
		return "", "", nil, errors.New("postgres not configured")
	}
	if err := s.ensureUserAccessByID(ctx, userID); err != nil {
		return "", "", nil, err
	}
	if err := s.requireSessionMFAState(ctx, userID, authMethods); err != nil {
		return "", "", nil, err
	}
	// Enforce session limit
	if s.opts.SessionMaxPerUser > 0 {
		if err = s.enforceSessionLimit(ctx, userID, s.opts.Issuer); err != nil {
			return "", "", nil, err
		}
	}
	// Generate token
	rt := randB64(32)
	hash := s.hashRefresh(rt)
	var expPtr *time.Time
	if s.opts.RefreshTokenDuration > 0 {
		exp := time.Now().Add(s.opts.RefreshTokenDuration)
		expPtr = &exp
	}
	var sid, fam string
	sid, err = newUUIDV7String()
	if err != nil {
		return "", "", nil, err
	}
	fam, err = newUUIDV7String()
	if err != nil {
		return "", "", nil, err
	}
	// Insert row
	row, err := s.q.SessionInsert(ctx, db.SessionInsertParams{
		ID:               sid,
		FamilyID:         fam,
		UserID:           userID,
		Issuer:           s.opts.Issuer,
		CurrentTokenHash: hash,
		ExpiresAt:        expPtr,
		UserAgent:        nullable(userAgent),
		IpAddr:           ipText(ip),
		AuthMethods:      normalizeAuthMethods(authMethods),
	})
	if err != nil {
		return "", "", nil, err
	}
	return row.ID, rt, expPtr, nil
}

// ExchangeRefreshToken rotates a refresh token and returns a new ID token + refresh token.
func (s *Service) ExchangeRefreshToken(ctx context.Context, refreshToken string, ua string, ip net.IP) (idToken string, expiresAt time.Time, newRefresh string, err error) {
	if s.pg == nil {
		return "", time.Time{}, "", errors.New("postgres not configured")
	}
	if strings.TrimSpace(refreshToken) == "" {
		return "", time.Time{}, "", errors.New("invalid refresh token")
	}
	h := s.hashRefresh(refreshToken)

	// Try current hash
	cur, err := s.q.SessionByCurrentTokenHash(ctx, db.SessionByCurrentTokenHashParams{CurrentTokenHash: h, Issuer: s.opts.Issuer})
	if err != nil {
		// Maybe reuse of previous token -> revoke family
		if prev, e2 := s.q.SessionByPreviousTokenHash(ctx, db.SessionByPreviousTokenHashParams{PreviousTokenHash: h, Issuer: s.opts.Issuer}); e2 == nil {
			s.revokeFamilyEnsured(ctx, prev.FamilyID, prev.UserID)
			return "", time.Time{}, "", errors.New("refresh token reuse detected")
		}
		return "", time.Time{}, "", errors.New("invalid refresh token")
	}
	sid, uid := cur.ID, cur.UserID
	if err := s.ensureUserAccessByID(ctx, uid); err != nil {
		return "", time.Time{}, "", err
	}
	if err := s.requireSessionMFAState(ctx, uid, cur.AuthMethods); err != nil {
		return "", time.Time{}, "", err
	}

	// Load email for ID token payload (best-effort)
	var email string
	if e, eErr := s.q.UserEmailByID(ctx, uid); eErr == nil && e != nil {
		email = *e
	}
	if ok, e := s.IsUserAllowed(ctx, uid); e != nil || !ok {
		if rErr := s.RevokeAllSessions(WithSessionRevokeReason(ctx, SessionRevokeReasonUserDisabled), uid, nil); rErr != nil {
			stdlog.Printf("[authkit/security] error: failed to revoke sessions for disabled user %s; in-flight access tokens stay valid until expiry (≤access TTL): %v", uid, rErr)
		}
		return "", time.Time{}, "", errors.New("user_disabled")
	}

	// Rotate: set previous = current, current = new
	newTok := randB64(32)
	newHash := s.hashRefresh(newTok)
	if err = s.q.SessionRotate(ctx, db.SessionRotateParams{CurrentTokenHash: newHash, UserAgent: nullable(ua), IpAddr: ipText(ip), ID: sid}); err != nil {
		return "", time.Time{}, "", err
	}

	// Mint new ID token
	claims := map[string]any{"sid": sid}
	accessToken, exp, err := s.IssueAccessToken(ctx, uid, email, claims)
	if err != nil {
		return "", time.Time{}, "", err
	}

	return accessToken, exp, newTok, nil
}

// Logout via refresh token was removed; use DELETE /auth/logout with sid claim instead.

// ListUserSessions lists active sessions for a user and issuer.
func (s *Service) ListUserSessions(ctx context.Context, userID string) ([]Session, error) {
	if s.pg == nil {
		return nil, nil
	}
	rows, err := s.q.SessionsListByUser(ctx, db.SessionsListByUserParams{UserID: userID, Issuer: s.opts.Issuer})
	if err != nil {
		return nil, err
	}
	var out []Session
	for _, r := range rows {
		out = append(out, Session{
			ID:                  r.ID,
			FamilyID:            r.FamilyID,
			CreatedAt:           r.CreatedAt,
			LastAuthenticatedAt: r.LastAuthenticatedAt,
			LastUsedAt:          r.LastUsedAt,
			ExpiresAt:           r.ExpiresAt,
			RevokedAt:           r.RevokedAt,
			UserAgent:           r.UserAgent,
			IPAddr:              r.IpAddr,
		})
	}
	return out, nil
}

func (s *Service) SessionFreshness(ctx context.Context, userID, sessionID string, now time.Time) (SessionFreshness, error) {
	if s.pg == nil {
		return SessionFreshness{}, errors.New("postgres not configured")
	}
	userID = strings.TrimSpace(userID)
	sessionID = strings.TrimSpace(sessionID)
	if userID == "" || sessionID == "" {
		return SessionFreshness{}, jwt.ErrTokenInvalidClaims
	}
	if now.IsZero() {
		now = time.Now()
	}

	fresh, err := s.q.SessionFreshSince(ctx, db.SessionFreshSinceParams{SessionID: sessionID, UserID: userID, Issuer: s.opts.Issuer})
	if err != nil {
		return SessionFreshness{}, err
	}

	remaining := SensitiveActionFreshAuthWindow - now.Sub(fresh.FreshSince)
	if remaining < 0 {
		remaining = 0
	}
	return SessionFreshness{
		LastAuthenticatedAt:           fresh.FreshSince,
		TimeUntilReauthRequired:       remaining,
		ReauthRequiredForSensitiveOps: remaining <= 0,
		AuthMethods:                   normalizeAuthMethods(fresh.AuthMethods),
	}, nil
}

func (s *Service) RequireFreshSession(ctx context.Context, userID, sessionID string, now time.Time) (SessionFreshness, error) {
	freshness, err := s.SessionFreshness(ctx, userID, sessionID, now)
	if err != nil {
		return SessionFreshness{}, err
	}
	if freshness.ReauthRequiredForSensitiveOps {
		return freshness, ErrReauthenticationRequired
	}
	return freshness, nil
}

func (s *Service) MarkSessionAuthenticated(ctx context.Context, userID, sessionID string) error {
	return s.MarkSessionAuthenticatedWithMethods(ctx, userID, sessionID, []string{"pwd"})
}

// MarkSessionAuthenticatedWithMethods refreshes the session's sensitive-action
// auth window and records how the user re-proved identity.
func (s *Service) MarkSessionAuthenticatedWithMethods(ctx context.Context, userID, sessionID string, authMethods []string) error {
	if s.pg == nil {
		return errors.New("postgres not configured")
	}
	userID = strings.TrimSpace(userID)
	sessionID = strings.TrimSpace(sessionID)
	if userID == "" || sessionID == "" {
		return jwt.ErrTokenInvalidClaims
	}
	n, err := s.q.SessionMarkAuthenticated(ctx, db.SessionMarkAuthenticatedParams{
		SessionID:   sessionID,
		UserID:      userID,
		Issuer:      s.opts.Issuer,
		AuthMethods: normalizeAuthMethods(authMethods),
	})
	if err != nil {
		return err
	}
	if n == 0 {
		return jwt.ErrTokenInvalidClaims
	}
	return nil
}

func normalizeAuthMethods(methods []string) []string {
	seen := map[string]struct{}{}
	out := make([]string, 0, len(methods))
	for _, method := range methods {
		method = strings.ToLower(strings.TrimSpace(method))
		if method == "" {
			continue
		}
		if _, ok := seen[method]; ok {
			continue
		}
		seen[method] = struct{}{}
		out = append(out, method)
	}
	if len(out) == 0 {
		return []string{"pwd"}
	}
	return out
}

// ResolveSessionByRefresh finds the session id for a presented refresh token, if valid and active.
func (s *Service) ResolveSessionByRefresh(ctx context.Context, refreshToken string) (string, error) {
	if s.pg == nil || strings.TrimSpace(refreshToken) == "" {
		return "", errors.New("not_found")
	}
	h := s.hashRefresh(refreshToken)
	sid, err := s.q.SessionIDByCurrentTokenHash(ctx, db.SessionIDByCurrentTokenHashParams{CurrentTokenHash: h, Issuer: s.opts.Issuer})
	if err != nil {
		return "", err
	}
	return sid, nil
}

func (s *Service) RevokeSessionByID(ctx context.Context, sessionID string) error {
	if s.pg == nil {
		return nil
	}
	reason := sessionRevokeReasonFromContext(ctx)
	if reason == nil {
		v := string(SessionRevokeReasonAdminRevoke)
		reason = &v
	}
	uid, err := s.q.SessionRevokeByID(ctx, db.SessionRevokeByIDParams{ID: sessionID, Issuer: s.opts.Issuer})
	if errors.Is(err, pgx.ErrNoRows) {
		return nil
	}
	if err != nil {
		return err
	}
	s.logSessionRevoked(ctx, uid, sessionID, reason)
	return nil
}

// RevokeSessionByIDForUser revokes a session by id ensuring it belongs to the user.
func (s *Service) RevokeSessionByIDForUser(ctx context.Context, userID, sessionID string) error {
	if s.pg == nil {
		return nil
	}
	reason := sessionRevokeReasonFromContext(ctx)
	if reason == nil {
		v := string(SessionRevokeReasonUserRevoke)
		reason = &v
	}
	sid, err := s.q.SessionRevokeByIDForUser(ctx, db.SessionRevokeByIDForUserParams{ID: sessionID, UserID: userID, Issuer: s.opts.Issuer})
	if errors.Is(err, pgx.ErrNoRows) {
		return nil
	}
	if err != nil {
		return err
	}
	s.logSessionRevoked(ctx, userID, sid, reason)
	return nil
}

func (s *Service) RevokeAllSessions(ctx context.Context, userID string, keepSessionID *string) error {
	if s.pg == nil {
		return nil
	}
	reason := sessionRevokeReasonFromContext(ctx)
	if reason == nil {
		v := string(SessionRevokeReasonUserRevokeAll)
		reason = &v
	}
	if keepSessionID != nil && *keepSessionID != "" {
		ids, err := s.q.SessionsRevokeAllExcept(ctx, db.SessionsRevokeAllExceptParams{UserID: userID, Issuer: s.opts.Issuer, ID: *keepSessionID})
		if err != nil {
			return err
		}
		for _, sid := range ids {
			s.logSessionRevoked(ctx, userID, sid, reason)
		}
		return nil
	}
	ids, err := s.q.SessionsRevokeAll(ctx, db.SessionsRevokeAllParams{UserID: userID, Issuer: s.opts.Issuer})
	if err != nil {
		return err
	}
	for _, sid := range ids {
		s.logSessionRevoked(ctx, userID, sid, reason)
	}
	return nil
}

// enforceSessionLimit enforces max active sessions per user using policy.
func (s *Service) enforceSessionLimit(ctx context.Context, userID, issuer string) error {
	if s.opts.SessionMaxPerUser <= 0 {
		return nil
	}
	count, err := s.q.SessionsCountActive(ctx, db.SessionsCountActiveParams{UserID: userID, Issuer: issuer})
	if err != nil {
		return err
	}
	if int(count) < s.opts.SessionMaxPerUser {
		return nil
	}
	// evict-oldest in a single statement
	excess := int(count) - s.opts.SessionMaxPerUser + 1
	if excess > 0 {
		ids, err := s.q.SessionsEvictOldest(ctx, db.SessionsEvictOldestParams{UserID: userID, Issuer: issuer, EvictCount: int64(excess)})
		if err != nil {
			return err
		}
		reason := string(SessionRevokeReasonEvicted)
		for _, sid := range ids {
			s.logSessionRevoked(ctx, userID, sid, &reason)
		}
	}
	return nil
}

func (s *Service) revokeFamily(ctx context.Context, familyID string) error {
	if s.pg == nil {
		return nil
	}
	rows, err := s.q.SessionsRevokeFamily(ctx, familyID)
	if err != nil {
		return err
	}
	reason := string(SessionRevokeReasonRefreshReuseDetected)
	for _, r := range rows {
		s.logSessionRevoked(ctx, r.UserID, r.ID, &reason)
	}
	return nil
}

// revokeFamilyEnsured revokes a session family on refresh-token-reuse detection,
// retrying once before logging a CRITICAL, page-able security event. The family
// revoke IS the refresh-token-theft defense (it kills every session descended
// from a reused refresh token), so a silently-swallowed failure would leave the
// attacker's stolen-but-rotated tokens valid. The reuse attempt itself is always
// rejected by the caller; this only ensures the rest of the family dies too.
func (s *Service) revokeFamilyEnsured(ctx context.Context, familyID, userID string) {
	if err := s.revokeFamily(ctx, familyID); err == nil {
		return
	} else {
		stdlog.Printf("[authkit/security] error: session family revoke failed after refresh-token reuse (family=%s user=%s); retrying: %v", familyID, userID, err)
	}
	if err := s.revokeFamily(ctx, familyID); err != nil {
		stdlog.Printf("[authkit/security] CRITICAL: session family revoke failed after retry (family=%s user=%s); stolen refresh tokens may remain valid — investigate immediately: %v", familyID, userID, err)
	}
}

func (s *Service) hashRefresh(token string) []byte {
	sum := sha256.Sum256([]byte(token))
	out := make([]byte, len(sum))
	copy(out, sum[:])
	return out
}

func nullable(s string) *string {
	if strings.TrimSpace(s) == "" {
		return nil
	}
	return &s
}

// ipText renders an IP for an inet column parameter (nil -> NULL).
func ipText(ip net.IP) *string {
	if ip == nil {
		return nil
	}
	v := ip.String()
	return &v
}

// Helper exposed for admin endpoints
func (s *Service) AdminListUserSessions(ctx context.Context, userID string) ([]Session, error) {
	return s.ListUserSessions(ctx, userID)
}

func (s *Service) AdminRevokeUserSessions(ctx context.Context, userID string) error {
	return s.RevokeAllSessions(ctx, userID, nil)
}
