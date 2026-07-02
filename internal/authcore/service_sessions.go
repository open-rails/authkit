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

	authkit "github.com/open-rails/authkit"
	"github.com/open-rails/authkit/internal/db"
)

// Session is defined in the lean authkit contract package (#138 inversion);
// aliased here so engine code keeps using the bare name.
type Session = authkit.Session

const SensitiveActionFreshAuthWindow = 15 * time.Minute

const (
	AssuranceLevelPassword = "urn:authkit:loa:1"
	AssuranceLevelMFA      = "urn:authkit:loa:2"
)

var ErrStepUpRequired = authkit.ErrStepUpRequired

type SessionFreshness struct {
	LastAuthenticatedAt           time.Time
	TimeUntilStepUpRequired       time.Duration
	StepUpRequiredForSensitiveOps bool
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
	return s.insertRefreshSession(ctx, userID, userAgent, ip, authMethods)
}

// insertRefreshSession generates a refresh token and inserts the session row,
// enforcing the per-user cap in one advisory-locked transaction. It performs NO
// live-user gate and NO MFA check — callers MUST have already loaded + gated the
// user (ensureUserAccess) and satisfied requireSessionMFAState. Split out of
// IssueRefreshSessionWithAuthMethods (#227) so the authenticated login / 2FA-verify
// paths (IssueAuthenticatedSession) can create the session and mint its access token
// from a SINGLE user load instead of re-reading + re-gating for each step.
func (s *Service) insertRefreshSession(ctx context.Context, userID, userAgent string, ip net.IP, authMethods []string) (sessionID, refreshToken string, expiresAt *time.Time, err error) {
	if s.pg == nil {
		return "", "", nil, errors.New("postgres not configured")
	}
	// Generate token
	rt := randB64(32)
	hash := s.hashRefresh(rt)
	var expPtr *time.Time
	if s.opts.RefreshTokenDuration > 0 {
		exp := time.Now().Add(s.opts.RefreshTokenDuration)
		expPtr = &exp
	}
	sid, err := newUUIDV7String()
	if err != nil {
		return "", "", nil, err
	}
	fam, err := newUUIDV7String()
	if err != nil {
		return "", "", nil, err
	}

	// Enforce the per-user session cap and insert the new session in ONE
	// transaction, serialized against concurrent creates for the same user by a
	// transaction-scoped advisory lock. Without the lock the count→evict→insert
	// steps race: N concurrent logins at the cap each read count==max, each evict
	// the same one oldest session, and each insert — leaving the user above
	// SessionMaxPerUser. The lock auto-releases at transaction end.
	tx, err := s.pg.Begin(ctx)
	if err != nil {
		return "", "", nil, err
	}
	defer tx.Rollback(ctx)
	q := db.New(db.ForSchema(tx, s.dbSchema()))

	var evicted []string
	if s.opts.SessionMaxPerUser > 0 {
		if lockErr := q.SessionCreateLock(ctx, userID+"|"+s.opts.Issuer); lockErr != nil {
			return "", "", nil, lockErr
		}
		evicted, err = s.enforceSessionLimitTx(ctx, q, userID, s.opts.Issuer)
		if err != nil {
			return "", "", nil, err
		}
	}

	row, err := q.SessionInsert(ctx, db.SessionInsertParams{
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
	if err := tx.Commit(ctx); err != nil {
		return "", "", nil, err
	}

	// Audit evictions after commit (best-effort; mirrors the post-commit logging in
	// AdminRecoverUser).
	if len(evicted) > 0 {
		reason := string(SessionRevokeReasonEvicted)
		for _, esid := range evicted {
			s.logSessionRevoked(ctx, userID, esid, &reason)
		}
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

	// Load + gate the user row ONCE for the whole issue path (#227). Previously the
	// banned/deleted/reserved gate, the ID-token email, the "still allowed" recheck,
	// and the access-token mint each independently re-read profiles.users (and
	// recomputed MFAStatus), so a single refresh read the user row 3×+ and MFA 2×.
	// Here we read the row once, gate it once, compute MFA once, and thread both
	// through the rest of the flow.
	//
	// ensureUserAccess still rejects banned/deleted/reserved users with ErrUserBanned
	// at this exact point — the security invariant is unchanged (and BanUser already
	// revokes a banned user's sessions, so their refresh token usually fails the
	// session lookup above first; this gate is the backstop). This single gate
	// subsumes the former trailing IsUserAllowed recheck, which applied identical
	// allow/deny logic to a SECOND read of the same row: with the row loaded once it
	// could only diverge on a concurrent ban landing mid-refresh (already handled by
	// BanUser's revoke) or a transient error on the redundant re-read — the latter
	// would have wrongly revoked every session on a DB blip.
	u, err := s.getUserByID(ctx, uid)
	if err != nil || u == nil {
		return "", time.Time{}, "", errOrUnauthorized(err)
	}
	if err := s.ensureUserAccess(ctx, u); err != nil {
		return "", time.Time{}, "", err
	}

	mfa, mfaErr := s.MFAStatus(ctx, uid)
	if err := s.requireSessionMFAStateWith(cur.AuthMethods, mfa, mfaErr); err != nil {
		// Carry the userID so the refresh handler can hand back a usable
		// enrollment token instead of a dead-end 403 (#148, note b).
		if errors.Is(err, ErrTwoFAEnrollmentRequired) {
			return "", time.Time{}, "", &TwoFAEnrollmentRequiredError{UserID: uid}
		}
		return "", time.Time{}, "", err
	}

	// (The former separate UserByID read here existed only to source an ID-token
	// email that IssueAccessToken then ignored — profile claims no longer ride in the
	// access token — so it is dropped entirely; u already holds u.Email if ever needed.)

	// Mint the new access token BEFORE rotating the refresh session. Minting reads
	// only pre-rotation state (identity, session freshness via sid, entitlements), so
	// the token is identical either way — but ordering the fallible mint first means a
	// mint failure leaves the session un-rotated and the caller's current refresh token
	// still valid (a retry succeeds), instead of stranding them on the now-"previous"
	// token and tripping reuse-detection (family revoke) on the next attempt.
	claims := map[string]any{"sid": sid}
	var mfaForToken *MFAStatus
	if mfaErr == nil {
		mfaForToken = &mfa
	}
	accessToken, exp, err := s.issueAccessTokenForUser(ctx, u, mfaForToken, claims, s.opts.AccessTokenDuration)
	if err != nil {
		return "", time.Time{}, "", err
	}

	// Rotate: set previous = current, current = new — as an atomic compare-and-swap
	// conditioned on the current hash we just read (h). If 0 rows change, another
	// concurrent refresh already rotated this session (benign double-submit) or it
	// was revoked; reject cleanly (the already-minted token is simply discarded) and
	// WITHOUT triggering family revoke (losing the race is not token reuse).
	newTok := randB64(32)
	newHash := s.hashRefresh(newTok)
	rotated, err := s.q.SessionRotate(ctx, db.SessionRotateParams{
		NewTokenHash:             newHash,
		UserAgent:                nullable(ua),
		IpAddr:                   ipText(ip),
		ID:                       sid,
		ExpectedCurrentTokenHash: h,
	})
	if err != nil {
		return "", time.Time{}, "", err
	}
	if rotated == 0 {
		return "", time.Time{}, "", errors.New("invalid refresh token")
	}

	return accessToken, exp, newTok, nil
}

// IssueAuthenticatedSession creates a refresh session AND mints its paired access
// token for an ALREADY-AUTHENTICATED user in one shot (#227). It loads + gates the
// user row (ensureUserAccess) and computes MFAStatus ONCE, threading both through the
// session-creation gate and the access-token mint — instead of the 2× user-read /
// 2× MFA-read that the separate IssueRefreshSession* + IssueAccessToken calls incurred
// on the password-login and 2FA-verify paths.
//
// authMethods records how the session was established (e.g. []string{"pwd"} for
// password login, []string{"pwd","otp","mfa"} after a verified second factor). extra
// is merged into the access token; the freshly-created session id is added as "sid".
// The banned/deleted/reserved gate and the MFA gate behave exactly as they do for the
// separate calls (same ErrUserBanned / ErrTwoFAEnrollmentRequired at the same point).
// Returns the session id so the caller can emit its own session-created audit log.
func (s *Service) IssueAuthenticatedSession(ctx context.Context, userID, userAgent string, ip net.IP, authMethods []string, extra map[string]any) (sessionID, refreshToken, accessToken string, accessExpiresAt time.Time, refreshExpiresAt *time.Time, err error) {
	if s.pg == nil {
		return "", "", "", time.Time{}, nil, errors.New("postgres not configured")
	}
	u, err := s.getUserByID(ctx, userID)
	if err != nil || u == nil {
		return "", "", "", time.Time{}, nil, errOrUnauthorized(err)
	}
	if err := s.ensureUserAccess(ctx, u); err != nil {
		return "", "", "", time.Time{}, nil, err
	}
	mfa, mfaErr := s.MFAStatus(ctx, userID)
	if err := s.requireSessionMFAStateWith(authMethods, mfa, mfaErr); err != nil {
		return "", "", "", time.Time{}, nil, err
	}

	sid, rt, refreshExp, err := s.insertRefreshSession(ctx, userID, userAgent, ip, authMethods)
	if err != nil {
		return "", "", "", time.Time{}, nil, err
	}

	// Copy caller extra so we never mutate their map, then stamp the new session id.
	claims := make(map[string]any, len(extra)+1)
	for k, v := range extra {
		claims[k] = v
	}
	claims["sid"] = sid
	var mfaForToken *MFAStatus
	if mfaErr == nil {
		mfaForToken = &mfa
	}
	accessToken, accessExp, err := s.issueAccessTokenForUser(ctx, u, mfaForToken, claims, s.opts.AccessTokenDuration)
	if err != nil {
		return "", "", "", time.Time{}, nil, err
	}
	return sid, rt, accessToken, accessExp, refreshExp, nil
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
		TimeUntilStepUpRequired:       remaining,
		StepUpRequiredForSensitiveOps: remaining <= 0,
		AuthMethods:                   normalizeAuthMethods(fresh.AuthMethods),
	}, nil
}

func (s *Service) RequireFreshSession(ctx context.Context, userID, sessionID string, now time.Time) (SessionFreshness, error) {
	freshness, err := s.SessionFreshness(ctx, userID, sessionID, now)
	if err != nil {
		return SessionFreshness{}, err
	}
	if freshness.StepUpRequiredForSensitiveOps {
		return freshness, ErrStepUpRequired
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

// enforceSessionLimitTx evicts the oldest sessions so that inserting one more keeps
// the user at or below SessionMaxPerUser. It runs on the caller's transaction-bound
// queries (q) — under the per-user advisory lock taken by the caller — so the count +
// evict + the subsequent insert observe a consistent view and the active count can
// never exceed the cap. Returns the evicted session ids for the caller to audit after
// commit (so a logging failure can't roll back the eviction).
func (s *Service) enforceSessionLimitTx(ctx context.Context, q *db.Queries, userID, issuer string) ([]string, error) {
	if s.opts.SessionMaxPerUser <= 0 {
		return nil, nil
	}
	count, err := q.SessionsCountActive(ctx, db.SessionsCountActiveParams{UserID: userID, Issuer: issuer})
	if err != nil {
		return nil, err
	}
	if int(count) < s.opts.SessionMaxPerUser {
		return nil, nil
	}
	// evict-oldest in a single statement so inserting one more lands at the cap
	excess := int(count) - s.opts.SessionMaxPerUser + 1
	if excess <= 0 {
		return nil, nil
	}
	ids, err := q.SessionsEvictOldest(ctx, db.SessionsEvictOldestParams{UserID: userID, Issuer: issuer, EvictCount: int64(excess)})
	if err != nil {
		return nil, err
	}
	return ids, nil
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
