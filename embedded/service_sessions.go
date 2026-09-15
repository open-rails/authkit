package embedded

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
func (s *Client) IssueRefreshSession(ctx context.Context, userID, userAgent string, ip net.IP) (sessionID, refreshToken string, expiresAt *time.Time, err error) {
	return s.IssueRefreshSessionWithAuthMethods(ctx, userID, userAgent, ip, []string{"pwd"})
}

// IssueRefreshSessionWithAuthMethods creates a refresh session and records the
// authentication methods that established it. Callers minting a session after
// MFA should pass e.g. []string{"pwd", "otp", "mfa"}.
func (s *Client) IssueRefreshSessionWithAuthMethods(ctx context.Context, userID, userAgent string, ip net.IP, authMethods []string) (sessionID, refreshToken string, expiresAt *time.Time, err error) {
	if s.pg == nil {
		return "", "", nil, errors.New("postgres not configured")
	}
	tx, err := s.pg.Begin(ctx)
	if err != nil {
		return "", "", nil, err
	}
	defer tx.Rollback(ctx)
	q := s.qtx(tx)
	if _, err := s.lockLoginAccount(ctx, q, userID, 0); err != nil {
		return "", "", nil, err
	}
	settings, settingsErr := s.get2FASettings(ctx, q, userID)
	status, statusErr := s.MFAStatusWith(settings, settingsErr)
	if err := s.requireSessionMFAStateOn(ctx, db.ForSchema(tx, s.dbSchema()), userID, authMethods, status, statusErr); err != nil {
		return "", "", nil, err
	}
	sid, rt, exp, evicted, err := s.insertRefreshSessionTx(ctx, q, userID, userAgent, ip, authMethods)
	if err != nil {
		return "", "", nil, err
	}
	if err := tx.Commit(ctx); err != nil {
		return "", "", nil, err
	}
	s.logSessionEvictions(ctx, userID, evicted)
	return sid, rt, exp, nil
}

// insertRefreshSessionTx is the one session insert/cap operation. Its caller
// owns the account lock, admission checks, commit and post-commit audit.
func (s *Client) insertRefreshSessionTx(ctx context.Context, q *db.Queries, userID, userAgent string, ip net.IP, authMethods []string) (string, string, *time.Time, []string, error) {
	rt := RandB64(32)
	var exp *time.Time
	if s.cfg.Token.RefreshTokenDuration > 0 {
		deadline := time.Now().Add(s.cfg.Token.RefreshTokenDuration)
		exp = &deadline
	}
	sid, err := newUUIDV7String()
	if err != nil {
		return "", "", nil, nil, err
	}
	family, err := newUUIDV7String()
	if err != nil {
		return "", "", nil, nil, err
	}
	var evicted []string
	if s.cfg.Token.SessionMaxPerUser > 0 {
		if err := q.SessionCreateLock(ctx, userID+"|"+s.cfg.Token.Issuer); err != nil {
			return "", "", nil, nil, err
		}
		evicted, err = s.enforceSessionLimitTx(ctx, q, userID, s.cfg.Token.Issuer)
		if err != nil {
			return "", "", nil, nil, err
		}
	}
	_, err = q.SessionInsert(ctx, db.SessionInsertParams{ID: sid, FamilyID: family, UserID: userID, Issuer: s.cfg.Token.Issuer, CurrentTokenHash: s.hashRefresh(rt), ExpiresAt: exp, UserAgent: nullable(userAgent), IpAddr: ipText(ip), AuthMethods: normalizeAuthMethods(authMethods)})
	return sid, rt, exp, evicted, err
}

func (s *Client) logSessionEvictions(ctx context.Context, userID string, evicted []string) {
	reason := string(SessionRevokeReasonEvicted)
	for _, id := range evicted {
		s.logSessionRevoked(ctx, userID, id, &reason)
	}
}

// ExchangeRefreshToken rotates a refresh token and returns a new ID token + refresh token.
func (s *Client) ExchangeRefreshToken(ctx context.Context, refreshToken string, ua string, ip net.IP) (idToken string, expiresAt time.Time, newRefresh string, err error) {
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
	newTok := RandB64(32)
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
func (s *Client) exchangeDemotedRefreshToken(ctx context.Context, refreshToken string, h []byte, ua string, ip net.IP) (string, time.Time, string, error) {
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
func (s *Client) graceSuccessorFor(presented string, prev db.SessionByHistoricalTokenHashRow) (string, bool) {
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
func (s *Client) issueSessionAccessToken(ctx context.Context, userID, sessionID string, authMethods []string) (string, time.Time, error) {
	u, err := s.getUserByID(ctx, userID)
	if err != nil || u == nil {
		return "", time.Time{}, errOrUnauthorized(err)
	}
	if err := s.ensureUserAccess(ctx, u); err != nil {
		return "", time.Time{}, err
	}
	mfa, mfaErr := s.MFAStatus(ctx, userID)
	if err := s.requireSessionMFAStateWith(ctx, userID, authMethods, mfa, mfaErr); err != nil {
		if errors.Is(err, ErrTwoFAEnrollmentRequired) || errors.Is(err, ErrTwoFARequired) {
			return "", time.Time{}, &MFAContinuationRequiredError{UserID: userID, SessionID: sessionID, Reason: err}
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

// IssueAuthenticatedSession issues a session for a trusted, already-authenticated
// caller. Interactive login flows additionally check their captured proof version
// before using the same transaction-owned issuance helper.
func (s *Client) IssueAuthenticatedSession(ctx context.Context, userID, userAgent string, ip net.IP, authMethods []string, extra map[string]any) (string, string, string, time.Time, *time.Time, error) {
	if s.pg == nil {
		return "", "", "", time.Time{}, nil, errors.New("postgres not configured")
	}
	tx, err := s.pg.Begin(ctx)
	if err != nil {
		return "", "", "", time.Time{}, nil, err
	}
	defer tx.Rollback(ctx)
	q := s.qtx(tx)
	u, err := s.lockLoginAccount(ctx, q, userID, 0)
	if err != nil {
		return "", "", "", time.Time{}, nil, err
	}
	settings, settingsErr := s.get2FASettings(ctx, q, userID)
	mfa, mfaErr := s.MFAStatusWith(settings, settingsErr)
	if err := s.requireSessionMFAStateOn(ctx, db.ForSchema(tx, s.dbSchema()), userID, authMethods, mfa, mfaErr); err != nil {
		return "", "", "", time.Time{}, nil, err
	}
	address := ""
	if ip != nil {
		address = ip.String()
	}
	session, exp, evicted, err := s.issueLoginSessionTx(ctx, q, u, mfa, LoginSessionInput{UserID: userID, UserAgent: userAgent, IP: address, AuthMethods: authMethods, Extra: extra})
	if err != nil {
		return "", "", "", time.Time{}, nil, err
	}
	if err := tx.Commit(ctx); err != nil {
		return "", "", "", time.Time{}, nil, err
	}
	s.logSessionEvictions(ctx, userID, evicted)
	return session.SessionID, session.RefreshToken, session.AccessToken, session.AccessExpiresAt, exp, nil
}

func (s *Client) issueLoginSessionTx(ctx context.Context, q *db.Queries, user *User, mfa MFAStatus, in LoginSessionInput) (IssuedSession, *time.Time, []string, error) {
	now := time.Now().UTC()
	if err := q.UserSetLastLogin(ctx, db.UserSetLastLoginParams{ID: user.ID, LastLogin: &now}); err != nil {
		return IssuedSession{}, nil, nil, err
	}
	sid, rt, exp, evicted, err := s.insertRefreshSessionTx(ctx, q, user.ID, in.UserAgent, net.ParseIP(in.IP), in.AuthMethods)
	if err != nil {
		return IssuedSession{}, nil, nil, err
	}
	fresh, err := q.SessionFreshSince(ctx, db.SessionFreshSinceParams{UserID: user.ID, SessionID: sid, Issuer: s.cfg.Token.Issuer})
	if err != nil {
		return IssuedSession{}, nil, nil, err
	}
	authTime, amr, acr := (SessionFreshness{LastAuthenticatedAt: fresh.FreshSince, AuthMethods: fresh.AuthMethods}).AssuranceClaims()
	extra := make(map[string]any, len(in.Extra)+1)
	for k, v := range in.Extra {
		extra[k] = v
	}
	extra["sid"] = sid
	if hasAuthMethod(amr, "swk") && hasAuthMethod(amr, "mfa") {
		mfa.Satisfied = true
	}
	token, accessExp, err := s.mintAccessTokenForUserWithAssurance(ctx, user, &mfa, extra, s.cfg.Token.AccessTokenDuration, &accessTokenAssurance{AuthTime: authTime, AMR: amr, ACR: acr})
	return IssuedSession{SessionID: sid, RefreshToken: rt, AccessToken: token, AccessExpiresAt: accessExp}, exp, evicted, err
}

// lockLoginAccount serializes proof completion with credential recovery. Zero
// expectedVersion is reserved for trusted host issuance, never an in-flight proof.
func (s *Client) lockLoginAccount(ctx context.Context, q *db.Queries, userID string, expectedVersion int64) (*User, error) {
	account, err := q.UserCredentialVersionForUpdate(ctx, userID)
	if err != nil {
		return nil, err
	}

	if account.DeletedAt != nil || account.BannedAt != nil && (account.BannedUntil == nil || account.BannedUntil.After(time.Now())) {
		return nil, ErrUserBanned
	}
	if expectedVersion > 0 && account.CredentialVersion != expectedVersion {
		return nil, jwt.ErrTokenUnverifiable
	}
	reserved, err := q.UserIsReserved(ctx, userID)
	if err != nil {
		return nil, err
	}
	if reserved {
		return nil, ErrUserBanned
	}
	row, err := q.UserByID(ctx, userID)
	if err != nil {
		return nil, err
	}
	return userFromByIDRow(row), nil
}

// Logout via refresh token was removed; use DELETE /auth/logout with sid claim instead.

// ListUserSessions lists active sessions for a user and issuer.
func (s *Client) ListUserSessions(ctx context.Context, userID string) ([]Session, error) {
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

func (s *Client) SessionFreshness(ctx context.Context, userID, sessionID string, now time.Time) (SessionFreshness, error) {
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

func (s *Client) MarkSessionAuthenticated(ctx context.Context, userID, sessionID string) error {
	return s.MarkSessionAuthenticatedWithMethods(ctx, userID, sessionID, []string{"pwd"})
}

// MarkSessionAuthenticatedWithMethods refreshes the session's sensitive-action
// auth window and records how the user re-proved identity.
func (s *Client) MarkSessionAuthenticatedWithMethods(ctx context.Context, userID, sessionID string, authMethods []string) error {
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

// RevokeSessionByIDForUser revokes a session by id ensuring it belongs to the user.
func (s *Client) RevokeSessionByIDForUser(ctx context.Context, userID, sessionID string) error {
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

func (s *Client) RevokeAllSessions(ctx context.Context, userID string, keepSessionID *string) error {
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
func (s *Client) enforceSessionLimitTx(ctx context.Context, q *db.Queries, userID, issuer string) ([]string, error) {
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

func (s *Client) revokeFamily(ctx context.Context, familyID string) error {
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
func (s *Client) revokeFamilyEnsured(ctx context.Context, familyID, userID string) {
	if err := s.revokeFamily(ctx, familyID); err == nil {
		return
	} else {
		stdlog.Printf("[authkit/security] error: session family revoke failed after refresh-token reuse (family=%s user=%s); retrying: %v", familyID, userID, err)
	}
	if err := s.revokeFamily(ctx, familyID); err != nil {
		stdlog.Printf("[authkit/security] CRITICAL: session family revoke failed after retry (family=%s user=%s); stolen refresh tokens may remain valid — investigate immediately: %v", familyID, userID, err)
	}
}

func (s *Client) hashRefresh(token string) []byte {
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

func (s *Client) AdminRevokeUserSessions(ctx context.Context, userID string) error {
	return s.RevokeAllSessions(ctx, userID, nil)
}
