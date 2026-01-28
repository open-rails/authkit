package core

import (
	"context"
	"crypto/sha256"
	"errors"
	"net"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
)

// Session represents a sanitized session view (no tokens).
type Session struct {
	ID         string
	FamilyID   string
	CreatedAt  time.Time
	LastUsedAt time.Time
	ExpiresAt  *time.Time
	RevokedAt  *time.Time
	UserAgent  *string
	IPAddr     *string
}

// IssueRefreshSession creates a session row and returns a new refresh token string.
func (s *Service) IssueRefreshSession(ctx context.Context, userID, userAgent string, ip net.IP) (sessionID, refreshToken string, expiresAt *time.Time, err error) {
	if s.pg == nil {
		return "", "", nil, errors.New("postgres not configured")
	}
	if err := s.ensureUserAccessByID(ctx, userID); err != nil {
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
	var ipstr *string
	if ip != nil {
		v := ip.String()
		ipstr = &v
	}
	// Insert row
	q := `INSERT INTO profiles.refresh_sessions (user_id, issuer, current_token_hash, expires_at, user_agent, ip_addr)
          VALUES ($1,$2,$3,$4,$5,$6)
          RETURNING id::text, family_id::text`
	if err = s.pg.QueryRow(ctx, q, userID, s.opts.Issuer, hash, expPtr, nullable(userAgent), ipstr).Scan(&sid, &fam); err != nil {
		return "", "", nil, err
	}
	return sid, rt, expPtr, nil
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
	var sid, uid, email string
	var fam string
	sel := `SELECT id::text, user_id, family_id::text FROM profiles.refresh_sessions
            WHERE current_token_hash=$1 AND issuer=$2 AND revoked_at IS NULL AND (expires_at IS NULL OR expires_at>now())`
	row := s.pg.QueryRow(ctx, sel, h, s.opts.Issuer)
	if err = row.Scan(&sid, &uid, &fam); err != nil {
		// Maybe reuse of previous token -> revoke family
		var sidPrev, uidPrev, famPrev string
		selPrev := `SELECT id::text, user_id, family_id::text FROM profiles.refresh_sessions
                    WHERE previous_token_hash=$1 AND issuer=$2 AND revoked_at IS NULL`
		if e2 := s.pg.QueryRow(ctx, selPrev, h, s.opts.Issuer).Scan(&sidPrev, &uidPrev, &famPrev); e2 == nil {
			_ = s.revokeFamily(ctx, famPrev)
			return "", time.Time{}, "", errors.New("refresh token reuse detected")
		}
		return "", time.Time{}, "", errors.New("invalid refresh token")
	}
	if err := s.ensureUserAccessByID(ctx, uid); err != nil {
		return "", time.Time{}, "", err
	}

	// Load email for ID token payload (best-effort)
	if s.pg != nil {
		_ = s.pg.QueryRow(ctx, `SELECT email FROM profiles.users WHERE id=$1`, uid).Scan(&email)
	}
	if ok, e := s.IsUserAllowed(ctx, uid); e != nil || !ok {
		_ = s.RevokeAllSessions(WithSessionRevokeReason(ctx, SessionRevokeReasonUserDisabled), uid, nil)
		return "", time.Time{}, "", errors.New("user_disabled")
	}

	// Rotate: set previous = current, current = new
	newTok := randB64(32)
	newHash := s.hashRefresh(newTok)
	upd := `UPDATE profiles.refresh_sessions
            SET previous_token_hash=current_token_hash, current_token_hash=$1, last_used_at=now(), user_agent=$2, ip_addr=$3
            WHERE id=$4 AND revoked_at IS NULL`
	if _, err = s.pg.Exec(ctx, upd, newHash, nullable(ua), ip, sid); err != nil {
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
	q := `SELECT id::text, family_id::text, created_at, last_used_at, expires_at, revoked_at,
                 user_agent, COALESCE(NULLIF(host(ip_addr)::text,''), NULL)
          FROM profiles.refresh_sessions
          WHERE user_id=$1 AND issuer=$2 AND (revoked_at IS NULL)`
	rows, err := s.pg.Query(ctx, q, userID, s.opts.Issuer)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Session
	for rows.Next() {
		var sID, fam string
		var created, lastUsed time.Time
		var expires, revoked *time.Time
		var ua, ip *string
		if err := rows.Scan(&sID, &fam, &created, &lastUsed, &expires, &revoked, &ua, &ip); err != nil {
			return nil, err
		}
		out = append(out, Session{ID: sID, FamilyID: fam, CreatedAt: created, LastUsedAt: lastUsed, ExpiresAt: expires, RevokedAt: revoked, UserAgent: ua, IPAddr: ip})
	}
	return out, rows.Err()
}

// ResolveSessionByRefresh finds the session id for a presented refresh token, if valid and active.
func (s *Service) ResolveSessionByRefresh(ctx context.Context, refreshToken string) (string, error) {
	if s.pg == nil || strings.TrimSpace(refreshToken) == "" {
		return "", errors.New("not_found")
	}
	h := s.hashRefresh(refreshToken)
	var sid string
	err := s.pg.QueryRow(ctx, `SELECT id::text FROM profiles.refresh_sessions WHERE current_token_hash=$1 AND issuer=$2 AND revoked_at IS NULL AND (expires_at IS NULL OR expires_at>now())`, h, s.opts.Issuer).Scan(&sid)
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
	var uid string
	err := s.pg.QueryRow(ctx, `UPDATE profiles.refresh_sessions SET revoked_at=now() WHERE id=$1 AND issuer=$2 AND revoked_at IS NULL RETURNING user_id::text`, sessionID, s.opts.Issuer).Scan(&uid)
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
	var sid string
	err := s.pg.QueryRow(ctx, `UPDATE profiles.refresh_sessions SET revoked_at=now() WHERE id=$1 AND user_id=$2 AND issuer=$3 AND revoked_at IS NULL RETURNING id::text`, sessionID, userID, s.opts.Issuer).Scan(&sid)
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
		rows, err := s.pg.Query(ctx, `UPDATE profiles.refresh_sessions SET revoked_at=now()
			WHERE user_id=$1 AND issuer=$2 AND id<>$3 AND revoked_at IS NULL
			RETURNING id::text`, userID, s.opts.Issuer, *keepSessionID)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var sid string
			if err := rows.Scan(&sid); err != nil {
				return err
			}
			s.logSessionRevoked(ctx, userID, sid, reason)
		}
		if err := rows.Err(); err != nil {
			return err
		}
		return nil
	}
	rows, err := s.pg.Query(ctx, `UPDATE profiles.refresh_sessions SET revoked_at=now()
		WHERE user_id=$1 AND issuer=$2 AND revoked_at IS NULL
		RETURNING id::text`, userID, s.opts.Issuer)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var sid string
		if err := rows.Scan(&sid); err != nil {
			return err
		}
		s.logSessionRevoked(ctx, userID, sid, reason)
	}
	return rows.Err()
}

// enforceSessionLimit enforces max active sessions per user using policy.
func (s *Service) enforceSessionLimit(ctx context.Context, userID, issuer string) error {
	if s.opts.SessionMaxPerUser <= 0 {
		return nil
	}
	// Probe query left here for reference; count-based approach used below
	// If count > max, evict (or reject). We probe by skipping max-1 and fetching the next oldest.
	// More explicit approach: count then decide.
	var count int
	if err := s.pg.QueryRow(ctx, `SELECT count(*) FROM profiles.refresh_sessions WHERE user_id=$1 AND issuer=$2 AND revoked_at IS NULL AND (expires_at IS NULL OR expires_at>now())`, userID, issuer).Scan(&count); err != nil {
		return err
	}
	if count < s.opts.SessionMaxPerUser {
		return nil
	}
	// evict-oldest in a single statement
	excess := count - s.opts.SessionMaxPerUser + 1
	if excess > 0 {
		rows, err := s.pg.Query(ctx, `UPDATE profiles.refresh_sessions SET revoked_at=now()
			WHERE id IN (
				SELECT id FROM profiles.refresh_sessions
				WHERE user_id=$1 AND issuer=$2 AND revoked_at IS NULL
				  AND (expires_at IS NULL OR expires_at>now())
				ORDER BY last_used_at ASC
				LIMIT $3
			)
			RETURNING id::text`, userID, issuer, excess)
		if err != nil {
			return err
		}
		defer rows.Close()
		reason := string(SessionRevokeReasonEvicted)
		for rows.Next() {
			var sid string
			if err := rows.Scan(&sid); err != nil {
				return err
			}
			s.logSessionRevoked(ctx, userID, sid, &reason)
		}
		if err := rows.Err(); err != nil {
			return err
		}
	}
	return nil
}

func (s *Service) revokeFamily(ctx context.Context, familyID string) error {
	if s.pg == nil {
		return nil
	}
	rows, err := s.pg.Query(ctx, `UPDATE profiles.refresh_sessions SET revoked_at=now()
		WHERE family_id=$1 AND revoked_at IS NULL
		RETURNING id::text, user_id::text`, familyID)
	if err != nil {
		return err
	}
	defer rows.Close()
	reason := string(SessionRevokeReasonRefreshReuseDetected)
	for rows.Next() {
		var sid, uid string
		if err := rows.Scan(&sid, &uid); err != nil {
			return err
		}
		s.logSessionRevoked(ctx, uid, sid, &reason)
	}
	return rows.Err()
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

// Helper exposed for admin endpoints
func (s *Service) AdminListUserSessions(ctx context.Context, userID string) ([]Session, error) {
	return s.ListUserSessions(ctx, userID)
}

func (s *Service) AdminRevokeUserSessions(ctx context.Context, userID string) error {
	return s.RevokeAllSessions(ctx, userID, nil)
}
