package authcore

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"errors"
	"fmt"
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
	if s.cfg.Token.RefreshTokenDuration > 0 {
		exp := time.Now().Add(s.cfg.Token.RefreshTokenDuration)
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
	if s.cfg.Token.SessionMaxPerUser > 0 {
		if lockErr := q.SessionCreateLock(ctx, userID+"|"+s.cfg.Token.Issuer); lockErr != nil {
			return "", "", nil, lockErr
		}
		evicted, err = s.enforceSessionLimitTx(ctx, q, userID, s.cfg.Token.Issuer)
		if err != nil {
			return "", "", nil, err
		}
	}

	row, err := q.SessionInsert(ctx, db.SessionInsertParams{
		ID:               sid,
		FamilyID:         fam,
		UserID:           userID,
		Issuer:           s.cfg.Token.Issuer,
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

	// Audit evictions after commit (best-effort).
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
	cur, err := s.q.SessionByCurrentTokenHash(ctx, db.SessionByCurrentTokenHashParams{CurrentTokenHash: h, Issuer: s.cfg.Token.Issuer})
	if errors.Is(err, pgx.ErrNoRows) {
		// No longer current: either a concurrent refresh demoted it a moment ago
		// (grace re-delivery) or it is genuine reuse (family revoke).
		return s.exchangeDemotedRefreshToken(ctx, refreshToken, h, ua, ip)
	}
	if err != nil {
		return "", time.Time{}, "", fmt.Errorf("find current refresh session: %w", err)
	}
	sid, uid := cur.ID, cur.UserID

	// Gate the identity and mint the new access token BEFORE rotating the refresh
	// session (issueSessionAccessToken reads the user row and MFA status once each,
	// #227; the ErrUserBanned and session-MFA gates fire at exactly this point, and
	// an ErrTwoFAEnrollmentRequired still carries the userID so the refresh handler
	// can hand back a usable enrollment token instead of a dead-end 403, #148 note b).
	//
	// Minting reads only pre-rotation state, so the token is identical either way —
	// but ordering the fallible mint first means a mint failure leaves the session
	// un-rotated and the caller's current refresh token still valid (a retry
	// succeeds), instead of stranding them on the now-"previous" token.
	accessToken, exp, err := s.issueSessionAccessToken(ctx, uid, sid, cur.AuthMethods)
	if err != nil {
		return "", time.Time{}, "", err
	}

	// Rotate and archive the consumed hash as an atomic compare-and-swap
	// conditioned on the current hash we just read (h). If 0 rows change, another
	// concurrent refresh already rotated this session (benign double-submit) or it
	// was revoked; the already-minted token is discarded and the caller is answered
	// from the grace path below — never from family revoke (losing the race is not
	// token reuse).
	//
	// The rotation also seals the successor under the token it replaces (ak#274), so
	// that a racer who presents the same predecessor an instant from now is handed
	// THIS successor rather than a second chain of its own.
	newTok := randB64(32)
	newHash := s.hashRefresh(newTok)
	rotated, err := s.q.SessionRotate(ctx, db.SessionRotateParams{
		NewTokenHash:             newHash,
		UserAgent:                nullable(ua),
		IpAddr:                   ipText(ip),
		ID:                       sid,
		ExpectedCurrentTokenHash: h,
		PreviousSuccessorSealed:  sealGraceSuccessor(refreshToken, newTok),
	})
	if err != nil {
		return "", time.Time{}, "", err
	}
	if rotated == 0 {
		return s.exchangeDemotedRefreshToken(ctx, refreshToken, h, ua, ip)
	}

	return accessToken, exp, newTok, nil
}

// exchangeDemotedRefreshToken answers a token that is no longer `current`. Two
// causes reach here and they are NOT the same event:
//
//   - A concurrent refresh of the SAME token demoted it a moment ago — a shared
//     credential file, a retried request, a response lost in flight. Inside the
//     grace window the sealed successor opens and hashes to the row's current
//     hash, which proves this exact token rotated into it. Handing that successor
//     back is re-delivery of ONE credential, not a fork: every racer converges on
//     the same token, which is why a five-way race no longer leaves four dead
//     credentials and a revoked family behind it.
//   - Anything else is reuse, and the family is revoked exactly as before. A
//     stolen token replayed after the window is still caught, so the window is a
//     bounded delay in detection, never an exemption from it.
//
// Re-delivery never rotates again: every holder of one predecessor converges on
// the same successor. Older consumed hashes identify the family but cannot open
// the seal for the current successor, so advancing twice does not hide reuse.
func (s *Service) exchangeDemotedRefreshToken(ctx context.Context, refreshToken string, h []byte, ua string, ip net.IP) (string, time.Time, string, error) {
	prev, err := s.q.SessionByHistoricalTokenHash(ctx, db.SessionByHistoricalTokenHashParams{TokenHash: h, Issuer: s.cfg.Token.Issuer})
	if errors.Is(err, pgx.ErrNoRows) {
		reason := "refresh_token_unknown"
		s.LogSessionFailed(ctx, "", "", &reason, ipText(ip), nullable(ua))
		return "", time.Time{}, "", errors.New("invalid refresh token")
	}
	if err != nil {
		return "", time.Time{}, "", fmt.Errorf("find historical refresh session: %w", err)
	}
	successor, ok := s.graceSuccessorFor(refreshToken, prev)
	if !ok {
		s.revokeFamilyEnsured(ctx, prev.FamilyID, prev.UserID)
		return "", time.Time{}, "", errors.New("refresh token reuse detected")
	}
	accessToken, exp, err := s.issueSessionAccessToken(ctx, prev.UserID, prev.ID, prev.AuthMethods)
	if err != nil {
		return "", time.Time{}, "", err
	}
	return accessToken, exp, successor, nil
}

// graceSuccessorFor decides whether a demoted token is inside its rotation grace
// window and, if so, recovers the successor it rotated into. Every gate must hold:
// the window is enabled, the row carries a seal from a rotation that recorded one,
// the rotation is recent, the session has not expired, and — the load-bearing
// check — the unsealed value hashes to the row's CURRENT token hash. That last one
// makes the whole thing self-verifying: a seal that does not open to the live
// successor is not accepted on the strength of the timestamp alone.
func (s *Service) graceSuccessorFor(presented string, prev db.SessionByHistoricalTokenHashRow) (string, bool) {
	window := s.cfg.Token.RefreshRotationGrace
	if window <= 0 || len(prev.PreviousSuccessorSealed) == 0 || prev.PreviousRotatedAt == nil {
		return "", false
	}
	now := s.nowTime()
	if now.Sub(*prev.PreviousRotatedAt) > window {
		return "", false
	}
	if prev.ExpiresAt != nil && !prev.ExpiresAt.After(now) {
		return "", false
	}
	successor := openGraceSuccessor(presented, prev.PreviousSuccessorSealed)
	if !hmac.Equal(s.hashRefresh(successor), prev.CurrentTokenHash) {
		return "", false
	}
	return successor, true
}

// issueSessionAccessToken runs the identity gates for an EXISTING session and mints
// its access token, with the session id riding as the "sid" claim. Both refresh
// paths — normal rotation and grace re-delivery — go through here, so they cannot
// drift apart on who is allowed to hold a token.
//
// The user row and MFAStatus are read exactly ONCE (#227): the gate, the mint and
// the former trailing IsUserAllowed recheck used to re-read the same row 3×+. That
// recheck is deliberately gone — it applied identical allow/deny logic to a SECOND
// read and could only diverge on a ban landing mid-refresh (BanUser already revokes
// the sessions) or on a transient DB error, where it would have wrongly revoked
// everything. ensureUserAccess still rejects banned/deleted/reserved users with
// ErrUserBanned at exactly this point.
func (s *Service) issueSessionAccessToken(ctx context.Context, userID, sessionID string, authMethods []string) (string, time.Time, error) {
	u, err := s.getUserByID(ctx, userID)
	if err != nil || u == nil {
		return "", time.Time{}, errOrUnauthorized(err)
	}
	if err := s.ensureUserAccess(ctx, u); err != nil {
		return "", time.Time{}, err
	}
	mfa, mfaErr := s.MFAStatus(ctx, userID)
	if err := s.requireSessionMFAStateWith(ctx, userID, authMethods, mfa, mfaErr); err != nil {
		if errors.Is(err, ErrTwoFAEnrollmentRequired) {
			return "", time.Time{}, &TwoFAEnrollmentRequiredError{UserID: userID}
		}
		return "", time.Time{}, err
	}
	var mfaForToken *MFAStatus
	if mfaErr == nil {
		mfaForToken = &mfa
	}
	return s.mintAccessTokenForUser(ctx, u, mfaForToken, map[string]any{"sid": sessionID}, s.cfg.Token.AccessTokenDuration)
}

// graceSealDomain separates the seal keystream from hashRefresh's bare SHA-256 of
// the same token, so the hash the database stores can never double as the key that
// opens the seal.
const graceSealDomain = "authkit:refresh-rotation-grace:v1"

// sealGraceSuccessor wraps a freshly minted successor under a keystream derived
// from the token it replaces.
//
// The point of the construction is WHO can open it. The predecessor is 256 bits of
// randomness the database never stores — only its SHA-256 — so a dump of
// refresh_sessions yields the seal and a hash and unseals nothing; at-rest hashing
// is exactly as strong as it was before this column existed. The only party who can
// open the seal is one already presenting the predecessor, which is already the
// credential the successor continues. Re-delivery therefore grants no capability
// the presented token did not already carry, and the seal is one-time by
// construction: each predecessor is used as a key exactly once.
func sealGraceSuccessor(predecessor, successor string) []byte {
	ks := graceKeystream(predecessor, len(successor))
	out := make([]byte, len(successor))
	for i := range out {
		out[i] = successor[i] ^ ks[i]
	}
	return out
}

func openGraceSuccessor(predecessor string, sealed []byte) string {
	ks := graceKeystream(predecessor, len(sealed))
	out := make([]byte, len(sealed))
	for i := range out {
		out[i] = sealed[i] ^ ks[i]
	}
	return string(out)
}

func graceKeystream(predecessor string, n int) []byte {
	out := make([]byte, 0, n+sha256.Size)
	for block := byte(0); len(out) < n; block++ {
		m := hmac.New(sha256.New, []byte(predecessor))
		m.Write([]byte(graceSealDomain))
		m.Write([]byte{block})
		out = m.Sum(out)
	}
	return out[:n]
}

// IssueAuthenticatedSession creates a refresh session AND mints its paired access
// token for an ALREADY-AUTHENTICATED user in one shot (#227). It loads + gates the
// user row (ensureUserAccess) and computes MFAStatus ONCE, threading both through the
// session-creation gate and the access-token mint — instead of the 2× user-read /
// 2× MFA-read that the separate IssueRefreshSession* + MintAccessToken calls incurred
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
	if err := s.requireSessionMFAStateWith(ctx, userID, authMethods, mfa, mfaErr); err != nil {
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
	accessToken, accessExp, err := s.mintAccessTokenForUser(ctx, u, mfaForToken, claims, s.cfg.Token.AccessTokenDuration)
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
	rows, err := s.q.SessionsListByUser(ctx, db.SessionsListByUserParams{UserID: userID, Issuer: s.cfg.Token.Issuer})
	if err != nil {
		return nil, err
	}
	var out []Session
	for _, r := range rows {
		// LastAuthenticatedAt and RevokedAt are left at their zero value: the
		// session-list query no longer selects them (#230 — the handler never
		// renders them, and revoked_at is always NULL for the rows it returns).
		out = append(out, Session{
			ID:         r.ID,
			FamilyID:   r.FamilyID,
			CreatedAt:  r.CreatedAt,
			LastUsedAt: r.LastUsedAt,
			ExpiresAt:  r.ExpiresAt,
			UserAgent:  r.UserAgent,
			IPAddr:     r.IpAddr,
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

	fresh, err := s.q.SessionFreshSince(ctx, db.SessionFreshSinceParams{SessionID: sessionID, UserID: userID, Issuer: s.cfg.Token.Issuer})
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
		Issuer:      s.cfg.Token.Issuer,
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

func (s *Service) RevokeSessionByID(ctx context.Context, sessionID string) error {
	if s.pg == nil {
		return nil
	}
	reason := sessionRevokeReasonFromContext(ctx)
	if reason == nil {
		v := string(SessionRevokeReasonAdminRevoke)
		reason = &v
	}
	uid, err := s.q.SessionRevokeByID(ctx, db.SessionRevokeByIDParams{ID: sessionID, Issuer: s.cfg.Token.Issuer})
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
	sid, err := s.q.SessionRevokeByIDForUser(ctx, db.SessionRevokeByIDForUserParams{ID: sessionID, UserID: userID, Issuer: s.cfg.Token.Issuer})
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
		ids, err := s.q.SessionsRevokeAllExcept(ctx, db.SessionsRevokeAllExceptParams{UserID: userID, Issuer: s.cfg.Token.Issuer, ID: *keepSessionID})
		if err != nil {
			return err
		}
		for _, sid := range ids {
			s.logSessionRevoked(ctx, userID, sid, reason)
		}
		return nil
	}
	ids, err := s.q.SessionsRevokeAll(ctx, db.SessionsRevokeAllParams{UserID: userID, Issuer: s.cfg.Token.Issuer})
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
	if s.cfg.Token.SessionMaxPerUser <= 0 {
		return nil, nil
	}
	count, err := q.SessionsCountActive(ctx, db.SessionsCountActiveParams{UserID: userID, Issuer: issuer})
	if err != nil {
		return nil, err
	}
	if int(count) < s.cfg.Token.SessionMaxPerUser {
		return nil, nil
	}
	// evict-oldest in a single statement so inserting one more lands at the cap
	excess := int(count) - s.cfg.Token.SessionMaxPerUser + 1
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

func (s *Service) AdminRevokeUserSessions(ctx context.Context, userID string) error {
	return s.RevokeAllSessions(ctx, userID, nil)
}
