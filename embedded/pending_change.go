package embedded

import (
	"context"
	"encoding/json"
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

// One record per identity (#301): register kinds are keyed by the target (the
// user does not exist yet), change kinds by the user. The 6-digit code hash lives
// inside the record and is only ever compared against the record the caller
// addressed, so two strangers drawing the same code never share storage. Only the
// 256-bit link token gets a global pointer.
const (
	keyPendingChange     = "pending_change:rec:"  // +<kind>:<target|userID> -> pendingChange JSON
	keyPendingChangeLink = "pending_change:link:" // +<kind>:<linkHash> -> record key
	keyPendingChangeUser = "pending_change:user:" // +<kind>:<username> -> record key (register kinds)
)

// pendingChange is the unified record backing all four flows. Register kinds
// leave UserID empty and carry the signup payload; change kinds set UserID and
// leave the signup payload empty. Target is the email or phone being
// registered/changed-to.
type pendingChange struct {
	ID                 string `json:"id"`
	AccountInviteToken string `json:"account_invite_token,omitempty"`
	expected           []byte
	Kind               PendingChangeKind `json:"kind"`
	Target             string            `json:"target"`
	UserID             string            `json:"user_id,omitempty"`
	Username           string            `json:"username,omitempty"`
	PasswordHash       string            `json:"password_hash,omitempty"`
	PreferredLanguage  string            `json:"preferred_language,omitempty"`
	CodeHash           string            `json:"code_hash"`
	LinkHash           string            `json:"link_hash,omitempty"`
}

func (k PendingChangeKind) isRegister() bool {
	return k == KindRegisterEmail || k == KindRegisterPhone
}

func (k PendingChangeKind) isEmail() bool {
	return k == KindRegisterEmail || k == KindChangeEmail
}

func (k PendingChangeKind) defaultTTL() time.Duration {
	if k.isEmail() {
		return defaultEmailVerificationTTL
	}
	return defaultPhoneVerificationTTL
}

// normalizePendingTarget canonicalizes the target the same way the rest of the
// service does, so lookups by target are stable.
func normalizePendingTarget(kind PendingChangeKind, target string) string {
	if kind.isEmail() {
		return NormalizeEmail(target)
	}
	return NormalizePhone(target)
}

func pendingChangeKey(kind PendingChangeKind, id string) string {
	return keyPendingChange + string(kind) + ":" + id
}

func pendingChangeUserKey(kind PendingChangeKind, username string) string {
	return keyPendingChangeUser + string(kind) + ":" + strings.TrimSpace(username)
}

// Link pointers are namespaced per kind: the HTTP confirm handlers try each
// kind in turn with the same token, and a miss for one kind must never consume
// another kind's single-use pointer.
func pendingChangeLinkKey(kind PendingChangeKind, linkHash string) string {
	return keyPendingChangeLink + string(kind) + ":" + linkHash
}

func (rec pendingChange) key() string {
	if rec.Kind.isRegister() {
		return pendingChangeKey(rec.Kind, rec.Target)
	}
	return pendingChangeKey(rec.Kind, rec.UserID)
}

// storePendingChange writes a pending change under its identity key plus the
// link pointer and (register kinds) the username index. Any prior record on the
// same identity or username is cleared first so a re-request supersedes it.
func (s *Client) storePendingChange(ctx context.Context, rec pendingChange, ttl time.Duration) error {
	if !s.useEphemeralStore() {
		return fmt.Errorf("ephemeral store not configured")
	}
	if rec.CodeHash == "" && rec.LinkHash == "" {
		return fmt.Errorf("pending change without verification secret")
	}
	rec.ID = RandB64(16)
	if rec.Kind.isRegister() {
		rec.AccountInviteToken = accountRegistrationInviteTokenFromContext(ctx)
	}
	rec.Target = normalizePendingTarget(rec.Kind, rec.Target)
	if ttl <= 0 {
		ttl = rec.Kind.defaultTTL()
	}
	key := rec.key()

	s.deletePendingChange(ctx, key)
	if rec.Kind.isRegister() && rec.Username != "" {
		var old pendingChangeIndex
		if ok, _ := s.ephemGetJSON(ctx, pendingChangeUserKey(rec.Kind, rec.Username), &old); ok && old.Key != "" && old.Key != key {
			s.deletePendingChange(ctx, old.Key)
		}
	}

	if err := s.ephemSetJSON(ctx, key, rec, ttl); err != nil {
		return err
	}
	if rec.LinkHash != "" {
		if err := s.ephemSetString(ctx, pendingChangeLinkKey(rec.Kind, rec.LinkHash), key, ttl); err != nil {
			return err
		}
	}
	if rec.Kind.isRegister() && rec.Username != "" {
		_ = s.ephemSetJSON(ctx, pendingChangeUserKey(rec.Kind, rec.Username), pendingChangeIndex{Key: key, ID: rec.ID}, ttl)
	}
	return nil
}

func (s *Client) loadPendingChange(ctx context.Context, key string) (pendingChange, bool, error) {
	var rec pendingChange
	raw, ok, err := s.ephemReadJSON(ctx, key, &rec)
	rec.expected = raw
	return rec, ok && rec.ID != "", err
}

// findPendingChangeByTarget loads a register-kind record and asserts it really
// is the one issued for this target.
// findPendingChangeByTarget is the lookup-only form: a store failure reads as
// "not found". Confirm paths use pendingChangeByTarget so a backend failure is
// never counted as a bad guess (ak#324).
func (s *Client) findPendingChangeByTarget(ctx context.Context, kind PendingChangeKind, target string) (pendingChange, bool) {
	rec, ok, _ := s.pendingChangeByTarget(ctx, kind, target)
	return rec, ok
}

func (s *Client) pendingChangeByTarget(ctx context.Context, kind PendingChangeKind, target string) (pendingChange, bool, error) {
	target = normalizePendingTarget(kind, target)
	if !kind.isRegister() || target == "" {
		return pendingChange{}, false, nil
	}
	rec, ok, err := s.loadPendingChange(ctx, pendingChangeKey(kind, target))
	if err != nil {
		return pendingChange{}, false, err
	}
	if !ok || rec.Kind != kind || rec.Target != target {
		return pendingChange{}, false, nil
	}
	return rec, true, nil
}

func (s *Client) findPendingChangeByUser(ctx context.Context, kind PendingChangeKind, userID string) (pendingChange, bool) {
	rec, ok, _ := s.pendingChangeByUser(ctx, kind, userID)
	return rec, ok
}

func (s *Client) pendingChangeByUser(ctx context.Context, kind PendingChangeKind, userID string) (pendingChange, bool, error) {
	if kind.isRegister() || userID == "" {
		return pendingChange{}, false, nil
	}
	rec, ok, err := s.loadPendingChange(ctx, pendingChangeKey(kind, userID))
	if err != nil {
		return pendingChange{}, false, err
	}
	if !ok || rec.Kind != kind || rec.UserID != userID {
		return pendingChange{}, false, nil
	}
	return rec, true, nil
}

// pendingChangeUsernameTaken reports whether a register-kind pending change is
// holding the given username (used by availability/conflict checks).
type pendingChangeIndex struct {
	Key string
	ID  string
}

func (s *Client) pendingChangeUsernameTaken(ctx context.Context, username string) bool {
	if !s.useEphemeralStore() {
		return false
	}
	for _, kind := range []PendingChangeKind{KindRegisterEmail, KindRegisterPhone} {
		var index pendingChangeIndex
		if ok, _ := s.ephemGetJSON(ctx, pendingChangeUserKey(kind, username), &index); !ok {
			continue
		}
		rec, ok, _ := s.loadPendingChange(ctx, index.Key)
		if ok && rec.ID == index.ID && rec.Username == username {
			return true
		}
	}
	return false
}

// pendingChangeTargetTaken reports whether a register-kind pending change is
// holding the given email/phone target.
func (s *Client) pendingChangeTargetTaken(ctx context.Context, kind PendingChangeKind, target string) bool {
	_, ok := s.findPendingChangeByTarget(ctx, kind, target)
	return ok
}

func (s *Client) clearPendingIndexes(ctx context.Context, rec pendingChange) {
	if rec.LinkHash != "" {
		_ = s.ephemDel(ctx, pendingChangeLinkKey(rec.Kind, rec.LinkHash))
	}
	if rec.Kind.isRegister() && rec.Username != "" {
		value, _ := json.Marshal(pendingChangeIndex{Key: rec.key(), ID: rec.ID})
		_, _ = s.ephemeralStore.CompareAndConsume(ctx, pendingChangeUserKey(rec.Kind, rec.Username), value)
	}
}

func (s *Client) claimPendingChange(ctx context.Context, rec pendingChange) error {
	if err := s.claimProof(ctx, rec.key(), rec.expected); err != nil {
		return err
	}
	s.clearPendingIndexes(ctx, rec)
	return nil
}

func (s *Client) deletePendingChange(ctx context.Context, key string) {
	if rec, ok, _ := s.loadPendingChange(ctx, key); ok {
		_ = s.claimPendingChange(ctx, rec)
	}
}

func (s *Client) deletePendingChangeByTarget(ctx context.Context, kind PendingChangeKind, target string) {
	if !s.useEphemeralStore() || !kind.isRegister() {
		return
	}
	s.deletePendingChange(ctx, pendingChangeKey(kind, normalizePendingTarget(kind, target)))
}

func (s *Client) deletePendingChangeByUser(ctx context.Context, kind PendingChangeKind, userID string) {
	if !s.useEphemeralStore() || kind.isRegister() {
		return
	}
	s.deletePendingChange(ctx, pendingChangeKey(kind, userID))
}

// finalizePendingChange dispatches to the per-kind finalizer that completes the
// deferred change and returns the affected user's ID.
func (s *Client) finalizePendingChange(ctx context.Context, rec pendingChange, keepSessionID *string) (string, error) {
	if rec.Kind.isRegister() {
		ctx = contextWithAccountRegistrationInviteToken(ctx, rec.AccountInviteToken)
	}
	switch rec.Kind {
	case KindRegisterEmail:
		return s.finalizeRegisterEmail(ctx, rec)
	case KindRegisterPhone:
		return s.finalizeRegisterPhone(ctx, rec)
	case KindChangeEmail:
		return s.finalizeChangeEmail(ctx, rec, keepSessionID)
	case KindChangePhone:
		return s.finalizeChangePhone(ctx, rec, keepSessionID)
	default:
		return "", fmt.Errorf("unknown pending change kind: %s", rec.Kind)
	}
}

// consumePendingChangeCode finalizes the record the caller addressed when the
// typed code matches. A wrong code leaves the record intact; the per-identifier
// attempt caps bound guessing. keepSessionID is the confirming session a
// contact change must not revoke (nil for registrations and link confirms).
func (s *Client) consumePendingChangeCode(ctx context.Context, rec pendingChange, code string, keepSessionID *string) (string, error) {
	if !SecretEqual(rec.CodeHash, sha256Hex(code)) {
		return "", jwt.ErrTokenUnverifiable
	}
	if err := s.claimPendingChange(ctx, rec); err != nil {
		return "", err
	}
	return s.finalizePendingChange(ctx, rec, keepSessionID)
}

// consumePendingChangeByLink redeems the 256-bit link token: the pointer is
// consumed atomically (single-use), then the record it names must be of the
// expected kind and still carry that link hash.
func (s *Client) consumePendingChangeByLink(ctx context.Context, linkHash string, expectKind PendingChangeKind) (string, error) {
	key, ok := s.consumeLink(ctx, pendingChangeLinkKey(expectKind, linkHash))
	if !ok {
		return "", jwt.ErrTokenUnverifiable
	}
	rec, ok, err := s.loadPendingChange(ctx, key)
	if err != nil {
		return "", err
	}
	if !ok || rec.Kind != expectKind || !SecretEqual(rec.LinkHash, linkHash) {
		return "", jwt.ErrTokenUnverifiable
	}
	if err := s.claimPendingChange(ctx, rec); err != nil {
		return "", err
	}
	return s.finalizePendingChange(ctx, rec, nil)
}
