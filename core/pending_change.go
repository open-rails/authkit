package core

import (
	"context"
	"fmt"
	"strings"
	"time"

	jwt "github.com/golang-jwt/jwt/v5"
)

// PendingChangeKind identifies one of the four verification-gated "deferred
// change" flows. They all share the same shape — "hold a change until an
// emailed/texted code is verified, then finalize it" — so they share one record
// type, one ephemeral storage namespace, and one set of generic operations,
// differing only in their per-kind finalizer.
type PendingChangeKind string

const (
	KindRegisterEmail PendingChangeKind = "register_email"
	KindRegisterPhone PendingChangeKind = "register_phone"
	KindChangeEmail   PendingChangeKind = "change_email"
	KindChangePhone   PendingChangeKind = "change_phone"
)

// Single ephemeral key namespace for every pending change. Pending state is
// disposable and TTL-expiring, so it lives only in the ephemeral store (Redis
// when multi-instance, in-memory otherwise) — never in postgres.
const (
	keyPendingChangeToken  = "auth:pending_change:token:"  // +<tokenHash> -> pendingChange JSON
	keyPendingChangeTarget = "auth:pending_change:target:" // +<kind>:<target> -> canonical tokenHash
	keyPendingChangeUser   = "auth:pending_change:user:"   // +<kind>:<username> -> canonical tokenHash (register kinds)
	keyPendingChangeUID    = "auth:pending_change:uid:"     // +<kind>:<userID> -> canonical tokenHash (change kinds)
)

// pendingChange is the unified record backing all four flows. Register kinds
// leave UserID empty (the user does not exist yet) and carry the signup payload
// (Username/PasswordHash/PreferredLocale); change kinds set UserID and leave the
// signup payload empty. Target is the email or phone being registered/changed-to.
type pendingChange struct {
	Kind            PendingChangeKind `json:"kind"`
	Target          string            `json:"target"`
	UserID          string            `json:"user_id,omitempty"`
	Username        string            `json:"username,omitempty"`
	PasswordHash    string            `json:"password_hash,omitempty"`
	PreferredLocale string            `json:"preferred_locale,omitempty"`
	TokenHashes     []string          `json:"token_hashes,omitempty"`
}

func (k PendingChangeKind) isRegister() bool {
	return k == KindRegisterEmail || k == KindRegisterPhone
}

func (k PendingChangeKind) isEmail() bool {
	return k == KindRegisterEmail || k == KindChangeEmail
}

// normalizePendingTarget canonicalizes the target the same way the rest of the
// service does, so lookups by target are stable.
func normalizePendingTarget(kind PendingChangeKind, target string) string {
	if kind.isEmail() {
		return normalizeEmail(target)
	}
	return NormalizePhone(target)
}

func pendingChangeTargetKey(kind PendingChangeKind, target string) string {
	return keyPendingChangeTarget + string(kind) + ":" + normalizePendingTarget(kind, target)
}

func pendingChangeUserKey(kind PendingChangeKind, username string) string {
	return keyPendingChangeUser + string(kind) + ":" + strings.TrimSpace(username)
}

func pendingChangeUIDKey(kind PendingChangeKind, userID string) string {
	return keyPendingChangeUID + string(kind) + ":" + userID
}

// storePendingChange writes a pending change under all of its token hashes plus
// the relevant lookup indexes (target always; username for register kinds; uid
// for change kinds). Any prior pending change occupying the same indexes is
// cleared first so a re-request supersedes the old one.
func (s *Service) storePendingChange(ctx context.Context, rec pendingChange, tokenTTLs map[string]time.Duration) error {
	if !s.useEphemeralStore() {
		return fmt.Errorf("ephemeral store not configured")
	}
	rec.Target = normalizePendingTarget(rec.Kind, rec.Target)

	defaultTTL := defaultEmailVerificationTTL
	if !rec.Kind.isEmail() {
		defaultTTL = defaultPhoneVerificationTTL
	}
	normalizedTTLs, canonicalHash, maxTTL, err := normalizeTokenTTLs(tokenTTLs, defaultTTL)
	if err != nil {
		return err
	}

	// Supersede any existing pending change on the same indexes.
	s.deletePendingChangeByTarget(ctx, rec.Kind, rec.Target)
	if rec.Kind.isRegister() && rec.Username != "" {
		if old, ok, _ := s.ephemGetString(ctx, pendingChangeUserKey(rec.Kind, rec.Username)); ok && old != "" {
			s.deletePendingChangeByToken(ctx, old)
		}
	}
	if !rec.Kind.isRegister() && rec.UserID != "" {
		if old, ok, _ := s.ephemGetString(ctx, pendingChangeUIDKey(rec.Kind, rec.UserID)); ok && old != "" {
			s.deletePendingChangeByToken(ctx, old)
		}
	}

	rec.TokenHashes = uniqueTokenHashes(canonicalHash, nil)
	for tokenHash := range normalizedTTLs {
		rec.TokenHashes = uniqueTokenHashes(tokenHash, rec.TokenHashes)
	}

	for tokenHash, ttl := range normalizedTTLs {
		if err := s.ephemSetJSON(ctx, keyPendingChangeToken+tokenHash, rec, ttl); err != nil {
			return err
		}
	}
	_ = s.ephemSetString(ctx, pendingChangeTargetKey(rec.Kind, rec.Target), canonicalHash, maxTTL)
	if rec.Kind.isRegister() && rec.Username != "" {
		_ = s.ephemSetString(ctx, pendingChangeUserKey(rec.Kind, rec.Username), canonicalHash, maxTTL)
	}
	if !rec.Kind.isRegister() && rec.UserID != "" {
		_ = s.ephemSetString(ctx, pendingChangeUIDKey(rec.Kind, rec.UserID), canonicalHash, maxTTL)
	}
	return nil
}

func (s *Service) loadPendingChangeByToken(ctx context.Context, tokenHash string) (pendingChange, bool, error) {
	var rec pendingChange
	ok, err := s.ephemGetJSON(ctx, keyPendingChangeToken+tokenHash, &rec)
	return rec, ok, err
}

func (s *Service) findPendingChangeByTarget(ctx context.Context, kind PendingChangeKind, target string) (pendingChange, bool) {
	token, ok, err := s.ephemGetString(ctx, pendingChangeTargetKey(kind, target))
	if err != nil || !ok || token == "" {
		return pendingChange{}, false
	}
	rec, ok, err := s.loadPendingChangeByToken(ctx, token)
	if err != nil || !ok || rec.Kind != kind {
		return pendingChange{}, false
	}
	return rec, true
}

func (s *Service) findPendingChangeByUser(ctx context.Context, kind PendingChangeKind, userID string) (pendingChange, bool) {
	token, ok, err := s.ephemGetString(ctx, pendingChangeUIDKey(kind, userID))
	if err != nil || !ok || token == "" {
		return pendingChange{}, false
	}
	rec, ok, err := s.loadPendingChangeByToken(ctx, token)
	if err != nil || !ok || rec.Kind != kind || rec.UserID != userID {
		return pendingChange{}, false
	}
	return rec, true
}

// pendingChangeUsernameTaken reports whether a register-kind pending change is
// holding the given username (used by availability/conflict checks).
func (s *Service) pendingChangeUsernameTaken(ctx context.Context, username string) bool {
	if !s.useEphemeralStore() {
		return false
	}
	for _, kind := range []PendingChangeKind{KindRegisterEmail, KindRegisterPhone} {
		if v, ok, _ := s.ephemGetString(ctx, pendingChangeUserKey(kind, username)); ok && v != "" {
			return true
		}
	}
	return false
}

// pendingChangeTargetTaken reports whether a register-kind pending change is
// holding the given email/phone target.
func (s *Service) pendingChangeTargetTaken(ctx context.Context, kind PendingChangeKind, target string) bool {
	if !s.useEphemeralStore() {
		return false
	}
	v, ok, _ := s.ephemGetString(ctx, pendingChangeTargetKey(kind, target))
	return ok && v != ""
}

func (s *Service) deletePendingChangeByToken(ctx context.Context, tokenHash string) {
	rec, ok, _ := s.loadPendingChangeByToken(ctx, tokenHash)
	if !ok {
		_ = s.ephemDel(ctx, keyPendingChangeToken+tokenHash)
		return
	}
	for _, h := range uniqueTokenHashes(tokenHash, rec.TokenHashes) {
		_ = s.ephemDel(ctx, keyPendingChangeToken+h)
	}
	_ = s.ephemDel(ctx, pendingChangeTargetKey(rec.Kind, rec.Target))
	if rec.Kind.isRegister() && rec.Username != "" {
		_ = s.ephemDel(ctx, pendingChangeUserKey(rec.Kind, rec.Username))
	}
	if !rec.Kind.isRegister() && rec.UserID != "" {
		_ = s.ephemDel(ctx, pendingChangeUIDKey(rec.Kind, rec.UserID))
	}
}

func (s *Service) deletePendingChangeByTarget(ctx context.Context, kind PendingChangeKind, target string) {
	if !s.useEphemeralStore() {
		return
	}
	if token, ok, _ := s.ephemGetString(ctx, pendingChangeTargetKey(kind, target)); ok && token != "" {
		s.deletePendingChangeByToken(ctx, token)
	}
}

func (s *Service) deletePendingChangeByUser(ctx context.Context, kind PendingChangeKind, userID string) {
	if !s.useEphemeralStore() {
		return
	}
	if token, ok, _ := s.ephemGetString(ctx, pendingChangeUIDKey(kind, userID)); ok && token != "" {
		s.deletePendingChangeByToken(ctx, token)
	}
}

// finalizePendingChange dispatches to the per-kind finalizer that completes the
// deferred change and returns the affected user's ID. This is the single
// "registry" of finalizers (register_email/register_phone create the user;
// change_email/change_phone apply the new value to an existing user).
func (s *Service) finalizePendingChange(ctx context.Context, rec pendingChange) (string, error) {
	switch rec.Kind {
	case KindRegisterEmail:
		return s.finalizeRegisterEmail(ctx, rec)
	case KindRegisterPhone:
		return s.finalizeRegisterPhone(ctx, rec)
	case KindChangeEmail:
		return s.finalizeChangeEmail(ctx, rec)
	case KindChangePhone:
		return s.finalizeChangePhone(ctx, rec)
	default:
		return "", fmt.Errorf("unknown pending change kind: %s", rec.Kind)
	}
}

// consumePendingChangeByToken loads a pending change by token hash, runs its
// finalizer, and (on success) deletes the record. Used by link-token and
// code confirmation paths that don't need to pre-validate the caller.
func (s *Service) consumePendingChangeByToken(ctx context.Context, tokenHash string, expectKind PendingChangeKind) (string, error) {
	rec, ok, err := s.loadPendingChangeByToken(ctx, tokenHash)
	if err != nil || !ok {
		return "", jwt.ErrTokenUnverifiable
	}
	if expectKind != "" && rec.Kind != expectKind {
		return "", jwt.ErrTokenUnverifiable
	}
	uid, err := s.finalizePendingChange(ctx, rec)
	if err != nil {
		return "", err
	}
	s.deletePendingChangeByToken(ctx, tokenHash)
	return uid, nil
}
