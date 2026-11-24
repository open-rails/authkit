package engine

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/internal/contact"
	"github.com/open-rails/authkit/internal/secret"
)

// pendingChangeKind is what a verification code proves an address for: a
// pending sign-up, an account's own address, or a contact change. Codes live
// in verification challenges; only a pending sign-up keeps a record of its
// own, the hold its address and username are taken by until it is proven.
type pendingChangeKind string

const (
	kindVerifyEmail   pendingChangeKind = "verify_email"
	kindVerifyPhone   pendingChangeKind = "verify_phone"
	kindRegisterEmail pendingChangeKind = "register_email"
	kindRegisterPhone pendingChangeKind = "register_phone"
	kindChangeEmail   pendingChangeKind = "change_email"
	kindChangePhone   pendingChangeKind = "change_phone"
)

// One pending sign-up per address, keyed by it (the user does not exist yet),
// with its username indexed.
const (
	keyPendingChange     = "pending_change:rec:"  // +<kind>:<target> -> pendingChange JSON
	keyPendingChangeUser = "pending_change:user:" // +<kind>:<username> -> record key
)

// pendingChange is a pending sign-up (register kinds), or a contact change a
// challenge proved (change kinds: UserID, Version, Target) on its way to its
// finalizer. Target is the email or phone being registered or changed to.
type pendingChange struct {
	Version            int64  `json:"version,omitempty"`
	ID                 string `json:"id"`
	AccountInviteToken string `json:"account_invite_token,omitempty"`
	expected           []byte
	Kind               pendingChangeKind `json:"kind"`
	Target             string            `json:"target"`
	UserID             string            `json:"user_id,omitempty"`
	Username           string            `json:"username,omitempty"`
	PasswordHash       string            `json:"password_hash,omitempty"`
	PreferredLanguage  string            `json:"preferred_language,omitempty"`
	// Agreements a pending sign-up accepted, recorded when it is proven.
	Agreements []iam.AgreementRef `json:"agreements,omitempty"`
}

func (k pendingChangeKind) isRegister() bool {
	return k == kindRegisterEmail || k == kindRegisterPhone
}

func (k pendingChangeKind) isChange() bool {
	return k == kindChangeEmail || k == kindChangePhone
}

func (k pendingChangeKind) isEmail() bool {
	return k == kindRegisterEmail || k == kindChangeEmail || k == kindVerifyEmail
}

func (k pendingChangeKind) defaultTTL() time.Duration {
	if k.isEmail() {
		return defaultEmailVerificationTTL
	}
	return defaultPhoneVerificationTTL
}

// normalizePendingTarget canonicalizes the target the same way the rest of the
// service does, so lookups by target are stable.
func normalizePendingTarget(kind pendingChangeKind, target string) string {
	if kind.isEmail() {
		return contact.NormalizeEmail(target)
	}
	return contact.NormalizePhone(target)
}

func pendingChangeKey(kind pendingChangeKind, id string) string {
	return keyPendingChange + string(kind) + ":" + id
}

// Usernames are case-insensitive identities, so one pending hold covers every
// spelling of a name.
func pendingChangeUserKey(kind pendingChangeKind, username string) string {
	return keyPendingChangeUser + string(kind) + ":" + strings.ToLower(strings.TrimSpace(username))
}

func (rec pendingChange) key() string { return pendingChangeKey(rec.Kind, rec.Target) }

// storePendingChange writes a pending sign-up under its address plus the
// username index, and returns it. Any prior record on the same address or
// username is cleared first, and with it the codes sent for it.
func (s *Engine) storePendingChange(ctx context.Context, rec pendingChange, ttl time.Duration) (pendingChange, error) {
	if !s.useEphemeralStore() {
		return rec, fmt.Errorf("ephemeral store not configured")
	}
	if !rec.Kind.isRegister() {
		return rec, fmt.Errorf("pending change of kind %s is not stored", rec.Kind)
	}
	rec.ID = secret.Token(16)
	rec.AccountInviteToken = accountRegistrationInviteTokenFromContext(ctx)
	rec.Agreements = registrationAgreementsFromContext(ctx)
	rec.Target = normalizePendingTarget(rec.Kind, rec.Target)
	if ttl <= 0 {
		ttl = rec.Kind.defaultTTL()
	}
	key := rec.key()

	s.deletePendingChange(ctx, key)
	if rec.Username != "" {
		var old pendingChangeIndex
		if ok, _ := s.ephemGetJSON(ctx, pendingChangeUserKey(rec.Kind, rec.Username), &old); ok && old.Key != "" && old.Key != key {
			s.deletePendingChange(ctx, old.Key)
		}
	}

	raw, err := json.Marshal(rec)
	if err != nil {
		return rec, err
	}
	if err := s.ephemeral.Set(ctx, key, raw, ttl); err != nil {
		return rec, err
	}
	rec.expected = raw
	if rec.Username != "" {
		_ = s.ephemSetJSON(ctx, pendingChangeUserKey(rec.Kind, rec.Username), pendingChangeIndex{Key: key, ID: rec.ID}, ttl)
	}
	return rec, nil
}

// renewPendingChange gives rec a fresh lifetime, keeping the codes already
// sent for it good, and reports whether rec is still the record stored.
func (s *Engine) renewPendingChange(ctx context.Context, rec pendingChange) (bool, error) {
	ttl := rec.Kind.defaultTTL()
	if ok, err := s.ephemeral.Swap(ctx, rec.key(), rec.expected, rec.expected, ttl); err != nil || !ok {
		return false, err
	}
	if rec.Username != "" {
		_ = s.ephemSetJSON(ctx, pendingChangeUserKey(rec.Kind, rec.Username), pendingChangeIndex{Key: rec.key(), ID: rec.ID}, ttl)
	}
	return true, nil
}

func (s *Engine) loadPendingChange(ctx context.Context, key string) (pendingChange, bool, error) {
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
func (s *Engine) findPendingChangeByTarget(ctx context.Context, kind pendingChangeKind, target string) (pendingChange, bool) {
	rec, ok, _ := s.pendingChangeByTarget(ctx, kind, target)
	return rec, ok
}

func (s *Engine) pendingChangeByTarget(ctx context.Context, kind pendingChangeKind, target string) (pendingChange, bool, error) {
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

// pendingChangeUsernameTaken reports whether a register-kind pending change is
// holding the given username (used by availability/conflict checks).
type pendingChangeIndex struct {
	Key string
	ID  string
}

func (s *Engine) pendingChangeUsernameTaken(ctx context.Context, username string) bool {
	if !s.useEphemeralStore() {
		return false
	}
	for _, kind := range []pendingChangeKind{kindRegisterEmail, kindRegisterPhone} {
		var index pendingChangeIndex
		if ok, _ := s.ephemGetJSON(ctx, pendingChangeUserKey(kind, username), &index); !ok {
			continue
		}
		rec, ok, _ := s.loadPendingChange(ctx, index.Key)
		if ok && rec.ID == index.ID && strings.EqualFold(rec.Username, strings.TrimSpace(username)) {
			return true
		}
	}
	return false
}

// pendingChangeTargetTaken reports whether a register-kind pending change is
// holding the given email/phone target.
func (s *Engine) pendingChangeTargetTaken(ctx context.Context, kind pendingChangeKind, target string) bool {
	_, ok := s.findPendingChangeByTarget(ctx, kind, target)
	return ok
}

func (s *Engine) clearPendingIndexes(ctx context.Context, rec pendingChange) {
	if rec.Username != "" {
		value, _ := json.Marshal(pendingChangeIndex{Key: rec.key(), ID: rec.ID})
		_, _ = s.ephemeral.CompareAndConsume(ctx, pendingChangeUserKey(rec.Kind, rec.Username), value)
	}
}

func (s *Engine) claimPendingChange(ctx context.Context, rec pendingChange) error {
	if err := s.claimProof(ctx, rec.key(), rec.expected); err != nil {
		return err
	}
	s.clearPendingIndexes(ctx, rec)
	return nil
}

func (s *Engine) deletePendingChange(ctx context.Context, key string) {
	if rec, ok, _ := s.loadPendingChange(ctx, key); ok {
		_ = s.claimPendingChange(ctx, rec)
	}
}

func (s *Engine) deletePendingChangeByTarget(ctx context.Context, kind pendingChangeKind, target string) {
	if !s.useEphemeralStore() || !kind.isRegister() {
		return
	}
	s.deletePendingChange(ctx, pendingChangeKey(kind, normalizePendingTarget(kind, target)))
}

// finalizePendingChange dispatches a proven contact change to its finalizer
// and returns the affected user's ID.
func (s *Engine) finalizePendingChange(ctx context.Context, rec pendingChange, keepSessionID *string) (string, error) {
	switch rec.Kind {
	case kindChangeEmail:
		return s.finalizeChangeEmail(ctx, rec, keepSessionID)
	case kindChangePhone:
		return s.finalizeChangePhone(ctx, rec, keepSessionID)
	default:
		return "", fmt.Errorf("unknown pending change kind: %s", rec.Kind)
	}
}
