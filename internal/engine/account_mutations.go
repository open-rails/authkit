package engine

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	stdlog "log"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/riverqueue/river"

	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/internal/authflow"
	"github.com/open-rails/authkit/internal/contact"
	"github.com/open-rails/authkit/internal/db"
	"github.com/open-rails/authkit/internal/errmodel"
	"github.com/open-rails/authkit/internal/ident"
	"github.com/open-rails/authkit/internal/naming"
	"github.com/open-rails/authkit/internal/ops"
	"github.com/open-rails/authkit/internal/password"
	"github.com/open-rails/helpers/auth"
)

// Account mutations. Every one takes an identity and runs in one authority
// transaction: rule ACCT(p) (requireAccount: CAP p on root, outranking the
// target on root and covering its grants in every group it holds a role in),
// or the operation's self rule, then the change, then a sweep of the target's
// credentials (revokeCredentialsOf), so a key or link never outlives the
// account authority that issued it.

// accountRule relaxes rule ACCT for one mutation. The zero rule refuses the
// identity's own account (ErrCannotTargetSelf) and a root peer.
type accountRule uint8

const (
	selfRefused  accountRule = 0
	selfAllowed  accountRule = 1 << iota // one's own account needs only a live identity
	peersAllowed                         // coverage suffices: signing a peer out is containment, not a takeover
)

// accountTx is the transaction an account mutation applies its change in.
type accountTx struct {
	tx     pgx.Tx
	q      *db.Queries
	st     *permissionGroupStore // records events of the acting identity
	userID string                // the target, canonical
	system bool
	self   bool
	by     *string // the acting user; nil for the system
}

func (s *Engine) withAccountMutation(ctx context.Context, a auth.Identity, userID string, p iam.Perm, rule accountRule, apply func(at accountTx) error) error {
	return s.withAccountMutationIn(ctx, a, nil, userID, p, rule, apply)
}

// withAccountMutationIn is withAccountMutation inside host, the host's own
// transaction, when set (see withAuthorityMutationIn).
func (s *Engine) withAccountMutationIn(ctx context.Context, a auth.Identity, host pgx.Tx, userID string, p iam.Perm, rule accountRule, apply func(at accountTx) error) error {
	if err := requireIdentity(a); err != nil {
		return err
	}
	if err := s.requirePG(); err != nil {
		return err
	}
	userID, ok := canonicalUUID(userID)
	if !ok {
		return iam.ErrUserNotFound
	}
	var tx pgx.Tx
	var err error
	if host == nil {
		tx, err = s.beginAuthorityTransaction(ctx)
	} else {
		tx, err = s.joinHostTransaction(ctx, host)
	}
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	st := s.groupStoreFor(tx)
	st.who = a
	if err := s.lockAuthority(ctx, tx); err != nil {
		return err
	}
	at := accountTx{tx: tx, q: s.qtx(tx), st: st, userID: userID, system: stateOf(a).IsSystem(), by: subjectUserID(a)}
	at.self = at.by != nil && *at.by == userID
	switch {
	case at.self && rule&selfAllowed == 0:
		return iam.ErrCannotTargetSelf
	case at.self:
		rootID, err := s.rootGroup(ctx, st)
		if err != nil {
			return err
		}
		if _, err := s.identityAuthority(ctx, st, a, groupTarget{ID: rootID, Persona: iam.RootPersona()}); err != nil {
			return err
		}
	default:
		if err := s.requireAccount(ctx, st, a, userID, p, rule&peersAllowed != 0); err != nil {
			return err
		}
	}
	if _, err := at.q.UserCredentialVersionForUpdate(ctx, userID); errors.Is(err, pgx.ErrNoRows) {
		return iam.ErrUserNotFound
	} else if err != nil {
		return err
	}
	if err := apply(at); err != nil {
		return err
	}
	if err := s.revokeCredentialsOf(ctx, st, userID); err != nil {
		return err
	}
	if err := s.revokeUncoveredCredentials(ctx, st, st.touched...); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// subjectUserID is the account behind a, in canonical form, for self rules and
// audit columns; nil for the system and machines.
func subjectUserID(a auth.Identity) *string {
	s := stateOf(a)
	if !s.IsUser() {
		return nil
	}
	id := s.ID()
	if canonical, ok := canonicalUUID(id); ok {
		id = canonical
	}
	return &id
}

// CreateUser creates a native account: a host operation.
func (s *Engine) CreateUser(ctx context.Context, n iam.NewUser, opts ...ops.Option) (iam.User, error) {
	host, err := hostTx("CreateUser", opts)
	if err != nil {
		return iam.User{}, err
	}
	if err := s.requirePG(); err != nil {
		return iam.User{}, err
	}
	var email, phone *string
	if v := strings.TrimSpace(n.Email); v != "" {
		if err := contact.ValidateEmail(v); err != nil {
			return iam.User{}, err
		}
		v = contact.NormalizeEmail(v)
		email = &v
	}
	if v := strings.TrimSpace(n.Phone); v != "" {
		if err := contact.ValidatePhone(v); err != nil {
			return iam.User{}, err
		}
		v = contact.NormalizePhone(v)
		phone = &v
	}
	if (email == nil && n.EmailVerified) || (phone == nil && n.PhoneVerified) {
		return iam.User{}, errmodel.E(errmodel.CodeInvalidRequest, errmodel.WithParam("verified"))
	}
	username := strings.TrimSpace(n.Username)
	if err := naming.ValidateImport(s.cfg.Username, username); err != nil {
		return iam.User{}, err
	}
	var hash string
	if n.Password != "" {
		if err := s.ValidatePassword(n.Password, username, deref(email)); err != nil {
			return iam.User{}, err
		}
		var err error
		if hash, err = password.HashArgon2id(ctx, n.Password); err != nil {
			return iam.User{}, err
		}
	}
	userID, err := newUUIDV7String()
	if err != nil {
		return iam.User{}, err
	}
	if err := s.admitName(ctx, iam.NameAdmissionRequest{UserID: userID, RequestedName: username, Operation: iam.NameCreate}); err != nil {
		return iam.User{}, err
	}
	var tx pgx.Tx
	if host == nil {
		tx, err = s.pg.Begin(ctx)
	} else {
		tx, err = s.joinHostTransaction(ctx, host)
	}
	if err != nil {
		return iam.User{}, err
	}
	defer tx.Rollback(ctx)
	now := time.Now().UTC()
	err = s.qtx(tx).UserImportInsert(ctx, db.UserImportInsertParams{
		ID: userID, Email: email, PhoneNumber: phone, Username: &username, AtTime: s.namingNow(),
		EmailVerified: n.EmailVerified, PhoneVerified: n.PhoneVerified, PublicMetadata: []byte(`{}`), CreatedAt: now, UpdatedAt: now,
	})
	if err != nil {
		return iam.User{}, mapUserUniqueViolation(err)
	}
	if hash != "" {
		if err := s.qtx(tx).UserPasswordUpsert(ctx, db.UserPasswordUpsertParams{UserID: userID, PasswordHash: hash, HashAlgo: "argon2id"}); err != nil {
			return iam.User{}, err
		}
	}
	if err := s.emitEvents(ctx, tx, iam.SystemIdentity(), userEvent(iam.EventUserRegistered, userID)); err != nil {
		return iam.User{}, err
	}
	out, err := userIn(ctx, tx, userID)
	if err != nil {
		return iam.User{}, err
	}
	return out, tx.Commit(ctx)
}

// selfEditable are the UserUpdate fields an account may change on itself.
func selfEditable(u iam.UserUpdate) bool {
	return u.Email == nil && u.Phone == nil && u.Password == nil && u.EmailVerified == nil && u.PhoneVerified == nil && u.PasswordHash == nil
}

// UpdateUser changes an account under ACCT(root:users:manage). An account may
// change its own Username and PreferredLanguage (the rename policy
// applies to itself, not to staff renaming it); Password, PasswordHash and the verified flags are system-only
// (staff send a reset to the proven address instead). Setting a verified flag
// is the proof transition: on an account with no proven contact it first
// retires every pre-proof credential, and every address the flags set don't
// cover. Never set one on another system's word (see ImportUsers). A contact
// change never leaves an account with a second factor or MFA-required roles
// without a proven contact, since the next proof would retire its MFA, and
// never moves its email factor, which stays bound to the address it was
// proven for. Nothing is sent to the new address.
func (s *Engine) UpdateUser(ctx context.Context, a auth.Identity, userID string, u iam.UserUpdate, opts ...ops.Option) (iam.User, error) {
	if err := noOptions("UpdateUser", opts); err != nil {
		return iam.User{}, err
	}
	if !stateOf(a).IsSystem() && (u.EmailVerified != nil || u.PhoneVerified != nil || u.Password != nil || u.PasswordHash != nil) {
		return iam.User{}, iam.ErrInsufficientAuthority
	}
	if u.Password != nil && u.PasswordHash != nil {
		return iam.User{}, errmodel.E(errmodel.CodeInvalidRequest, errmodel.WithParam("password"))
	}
	self := selfRefused
	if selfEditable(u) {
		self = selfAllowed
	}
	var revoked userUpdateRevocations
	err := s.withAccountMutation(ctx, a, userID, ident.RootUsersManage, self, func(at accountTx) error {
		// A verified flag set is a proof, applied first: it records the
		// events of the addresses it drops, so the diff below starts after it.
		var err error
		if p := (proof{email: u.EmailVerified != nil && *u.EmailVerified, phone: u.PhoneVerified != nil && *u.PhoneVerified}); p.email || p.phone {
			if revoked.proven, err = s.retirePreProofCredentials(ctx, at.tx, a, at.userID, p, nil); err != nil {
				return err
			}
		}
		before, err := readAccountIdentity(ctx, at.tx, at.userID)
		if err != nil {
			return err
		}
		if revoked.password, err = s.applyUserUpdate(ctx, at, strings.TrimSpace(userID), u); err != nil {
			return err
		}
		changes, err := identityChanges(ctx, at.tx, at.userID, before)
		if err != nil {
			return err
		}
		return at.st.record(ctx, changes...)
	})
	if err != nil {
		return iam.User{}, err
	}
	s.logRevokedSessions(ctx, userID, revoked.proven, string(authflow.SessionRevokeReasonContactProven))
	s.logRevokedSessions(ctx, userID, revoked.password, string(authflow.SessionRevokeReasonAdminSetPassword))
	return s.User(ctx, iam.UserByID(userID), ops.IncludeDeleted())
}

// userUpdateRevocations are the sessions an update revoked, by cause.
type userUpdateRevocations struct{ proven, password []revokedSession }

// applyUserUpdate applies u after its proof, if any, and returns the sessions
// a password change revoked.
func (s *Engine) applyUserUpdate(ctx context.Context, at accountTx, userID string, u iam.UserUpdate) ([]revokedSession, error) {
	var revoked []revokedSession
	before, err := contactStateForUpdate(ctx, at.tx, userID)
	if err != nil {
		return revoked, err
	}
	if u.Username != nil {
		authority := normalRename
		switch {
		case at.system:
			authority = importRename
		case !at.self:
			authority = staffRename
		}
		if err := s.renameUsernameTx(ctx, at.tx, userID, strings.TrimSpace(*u.Username), authority); err != nil {
			return revoked, err
		}
	}
	if u.Email != nil {
		var email *string
		if v := strings.TrimSpace(*u.Email); v != "" {
			if err := contact.ValidateEmail(v); err != nil {
				return revoked, err
			}
			v = contact.NormalizeEmail(v)
			email = &v
		}
		if err := at.q.UserSetEmail(ctx, db.UserSetEmailParams{ID: userID, Email: email}); err != nil {
			return revoked, mapUserUniqueViolation(err)
		}
	}
	if u.Phone != nil {
		var phone *string
		if v := strings.TrimSpace(*u.Phone); v != "" {
			if err := contact.ValidatePhone(v); err != nil {
				return revoked, err
			}
			v = contact.NormalizePhone(v)
			phone = &v
		}
		if err := at.q.UserSetPhone(ctx, db.UserSetPhoneParams{ID: userID, PhoneNumber: phone}); err != nil {
			return revoked, mapUserUniqueViolation(err)
		}
	}
	if u.EmailVerified != nil {
		n, err := at.q.UserSetEmailVerifiedIfPresent(ctx, db.UserSetEmailVerifiedIfPresentParams{ID: userID, Verified: *u.EmailVerified})
		if err := verifiedFlagSet("email_verified", n, err); err != nil {
			return revoked, err
		}
	}
	if u.PhoneVerified != nil {
		n, err := at.q.UserSetPhoneVerifiedIfPresent(ctx, db.UserSetPhoneVerifiedIfPresentParams{ID: userID, Verified: *u.PhoneVerified})
		if err := verifiedFlagSet("phone_verified", n, err); err != nil {
			return revoked, err
		}
	}
	if u.Email != nil || u.Phone != nil || u.EmailVerified != nil || u.PhoneVerified != nil {
		if err := s.keepMFAHolderProven(ctx, at.tx, userID, before); err != nil {
			return revoked, err
		}
	}
	if u.PreferredLanguage != nil {
		var language *string
		if v := strings.TrimSpace(*u.PreferredLanguage); v != "" {
			normalized, err := authflow.NormalizePreferredLanguage(v)
			if err != nil {
				return revoked, errmodel.E(errmodel.CodeInvalidPreferredLanguage)
			}
			language = &normalized
		}
		if err := at.q.UserSetPreferredLanguage(ctx, db.UserSetPreferredLanguageParams{ID: userID, PreferredLanguage: language}); err != nil {
			return revoked, err
		}
	}
	if u.Password != nil || u.PasswordHash != nil {
		hash, algo, err := s.passwordForUpdate(ctx, at.q, userID, u)
		if err != nil {
			return revoked, err
		}
		revoked, err = s.mutateCredentialsTx(ctx, at.q, userID, nil, func(q *db.Queries, _ db.UserCredentialVersionForUpdateRow) error {
			return q.UserPasswordUpsert(ctx, db.UserPasswordUpsertParams{UserID: userID, PasswordHash: hash, HashAlgo: algo})
		})
		if err != nil {
			return revoked, err
		}
	}
	return revoked, nil
}

// verifiedFlagSet is the outcome of setting a verified flag: no row changed
// means the account has no address to verify.
func verifiedFlagSet(param string, changed int64, err error) error {
	if err == nil && changed == 0 {
		return errmodel.E(errmodel.CodeInvalidRequest, errmodel.WithParam(param))
	}
	return err
}

// keepMFAHolderProven refuses a contact change that leaves an account with a
// second factor, or holding MFA-required roles, without a proven contact: the
// next proof (a reset to the new address) would retire that factor, handing
// the account to whoever controls the address (H4, N10). before is the state
// read before the change, in the same transaction.
func (s *Engine) keepMFAHolderProven(ctx context.Context, tx pgx.Tx, userID string, before db.ContactStateRow) error {
	after, err := contactState(ctx, tx, userID)
	if err != nil || before.Unproven || !after.Unproven {
		return err
	}
	enrolled, err := db.New(tx).MFAUsable(ctx, userID)
	if err != nil {
		return err
	}
	if !enrolled {
		holds, err := s.userHoldsMFARequiredRole(ctx, tx, userID)
		if err != nil || !holds {
			return err
		}
	}
	return contactVerificationRequired(after.Identifier, after.Channel)
}

// passwordForUpdate validates a new password against the policy and the
// account's current identifiers, or an imported hash, and returns what to store.
func (s *Engine) passwordForUpdate(ctx context.Context, q *db.Queries, userID string, u iam.UserUpdate) (hash, algo string, err error) {
	if u.PasswordHash != nil {
		hash, algo = strings.TrimSpace(u.PasswordHash.Hash), string(u.PasswordHash.Algo)
		return hash, algo, validatePasswordHashForStorage(hash, algo)
	}
	user, err := q.UserByID(ctx, userID)
	if err != nil {
		return "", "", err
	}
	if err := s.ValidatePassword(*u.Password, deref(user.Username), deref(user.Email)); err != nil {
		return "", "", err
	}
	hash, err = password.HashArgon2id(ctx, *u.Password)
	return hash, "argon2id", err
}

// PatchPublicMetadata applies patch to the account's public metadata as an
// RFC 7396 JSON Merge Patch under ACCT(root:users:manage), never on oneself:
// objects merge recursively, a nil value deletes its key, and any other value
// (arrays included) replaces the one it names.
func (s *Engine) PatchPublicMetadata(ctx context.Context, a auth.Identity, userID string, patch map[string]any, opts ...ops.Option) error {
	host, err := hostTx("PatchPublicMetadata", opts)
	if err != nil {
		return err
	}
	raw, err := json.Marshal(patch)
	if err != nil {
		return err
	}
	doc, err := decodeJSONValue(raw)
	if err != nil {
		return err
	}
	return s.withAccountMutationIn(ctx, a, host, userID, ident.RootUsersManage, selfRefused, func(at accountTx) error {
		if len(patch) == 0 {
			return nil
		}
		current, err := at.q.UserPublicMetadata(ctx, at.userID)
		if err != nil {
			return err
		}
		target, err := decodeJSONValue(current)
		if err != nil {
			return err
		}
		merged, err := json.Marshal(mergePatch(target, doc))
		if err != nil {
			return err
		}
		return at.q.UserSetPublicMetadata(ctx, db.UserSetPublicMetadataParams{ID: at.userID, PublicMetadata: merged})
	})
}

// mergePatch is RFC 7396's MergePatch over decoded JSON.
func mergePatch(target, patch any) any {
	p, ok := patch.(map[string]any)
	if !ok {
		return patch
	}
	t, ok := target.(map[string]any)
	if !ok {
		t = map[string]any{}
	}
	for k, v := range p {
		if v == nil {
			delete(t, k)
		} else {
			t[k] = mergePatch(t[k], v)
		}
	}
	return t
}

// decodeJSONValue decodes a JSON value, keeping numbers exact.
func decodeJSONValue(raw []byte) (any, error) {
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	var v any
	err := d.Decode(&v)
	return v, err
}

// Ban bans an account under ACCT(root:users:ban) and revokes its sessions,
// device keys and every credential it issued, in one transaction. Nobody bans
// themselves, and the last usable owner of a group cannot be banned.
func (s *Engine) Ban(ctx context.Context, a auth.Identity, userID string, b iam.Ban, opts ...ops.Option) error {
	if err := noOptions("Ban", opts); err != nil {
		return err
	}
	now := time.Now().UTC()
	var until *time.Time
	if b.Until != nil {
		if !b.Until.After(now) {
			return iam.ErrInvalidUntil
		}
		t := b.Until.UTC()
		until = &t
	}
	var reason *string
	if r := strings.TrimSpace(b.Reason); r != "" {
		reason = &r
	}
	var revoked []revokedSession
	err := s.withAccountMutation(ctx, a, userID, ident.RootUsersBan, selfRefused, func(at accountTx) error {
		if b.KeepExisting {
			inForce, err := at.q.UserBanInForce(ctx, userID)
			if err != nil {
				return err
			}
			if inForce {
				return nil
			}
		}
		if err := s.refuseSubjectOwnerLoss(ctx, at.st, iam.UserSubject(userID)); err != nil {
			return err
		}
		if err := at.q.UserBan(ctx, db.UserBanParams{ID: userID, BannedAt: &now, BannedUntil: until, BanReason: reason, BannedBy: subjectUserID(a)}); err != nil {
			return err
		}
		var err error
		if revoked, err = s.revokeCredentialsTx(ctx, at.tx, userID); err != nil {
			return err
		}
		banned := userEvent(iam.EventUserBanned, at.userID)
		banned.Reason, banned.Until = deref(reason), until
		return at.st.record(ctx, banned)
	})
	if err != nil {
		return err
	}
	s.logRevokedSessions(ctx, userID, revoked, string(authflow.SessionRevokeReasonBanned))
	return nil
}

// Unban lifts a ban under ACCT(root:users:ban). Lifting a ban restores the
// account's authority, so it needs the same coverage as imposing one; nobody
// lifts their own ban.
func (s *Engine) Unban(ctx context.Context, a auth.Identity, userID string, opts ...ops.Option) error {
	host, err := hostTx("Unban", opts)
	if err != nil {
		return err
	}
	return s.withAccountMutationIn(ctx, a, host, userID, ident.RootUsersBan, selfRefused, func(at accountTx) error {
		inForce, err := at.q.UserBanInForce(ctx, at.userID)
		if err != nil {
			return err
		}
		if err := at.q.UserClearBan(ctx, userID); err != nil || !inForce {
			return err
		}
		return at.st.record(ctx, userEvent(iam.EventUserUnbanned, at.userID))
	})
}

// DeleteUsers soft-deletes accounts under ACCT(root:users:delete), starting
// the fixed recovery window; an account may delete itself, and only then can
// signing in undo it. Sessions, device keys and every credential the account
// issued are revoked. A repeat call
// keeps the original window. Per-item results; the error is a whole-call
// failure.
func (s *Engine) DeleteUsers(ctx context.Context, a auth.Identity, ids []string, opts ...ops.Option) ([]iam.OpResult, error) {
	if err := noOptions("DeleteUsers", opts); err != nil {
		return nil, err
	}
	out := make([]iam.OpResult, 0, len(ids))
	for _, id := range ids {
		out = append(out, iam.OpResult{ID: id, Err: s.deleteUser(ctx, a, id)})
	}
	return out, nil
}

func (s *Engine) deleteUser(ctx context.Context, a auth.Identity, userID string) error {
	client, err := s.deletionRiver()
	if err != nil {
		return err
	}
	if err := s.checkSelfDeletion(ctx, a, userID); err != nil {
		return err
	}
	var revoked []revokedSession
	err = s.withAccountMutation(ctx, a, userID, ident.RootUsersDelete, selfAllowed, func(at accountTx) error {
		var err error
		revoked, err = s.softDeleteTx(ctx, at, client, userID)
		return err
	})
	if err != nil {
		return err
	}
	s.logRevokedSessions(ctx, userID, revoked, string(authflow.SessionRevokeReasonSoftDeleted))
	return nil
}

// checkSelfDeletion asks Deps.DeletionCheck before a user deletes their own
// live account: a refusal is deletion_refused, any other failure fails closed.
func (s *Engine) checkSelfDeletion(ctx context.Context, a auth.Identity, userID string) error {
	by := subjectUserID(a)
	id, ok := canonicalUUID(userID)
	if s.deletionCheck == nil || by == nil || !ok || *by != id {
		return nil
	}
	if u, err := s.q.UserByID(ctx, id); err != nil || u.DeletedAt != nil {
		return nil
	}
	err := s.deletionCheck(ctx, id)
	switch {
	case err == nil:
		return nil
	case errors.Is(err, iam.ErrDeletionRefused):
		return err
	}
	return errmodel.Internal("deletion_check", err)
}

func (s *Engine) softDeleteTx(ctx context.Context, at accountTx, client *river.Client[pgx.Tx], userID string) ([]revokedSession, error) {
	if err := s.refuseSubjectOwnerLoss(ctx, at.st, iam.UserSubject(userID)); err != nil {
		return nil, err
	}
	user, err := at.q.UserCredentialVersionForUpdate(ctx, userID)
	if err != nil {
		return nil, err
	}
	if user.DeletedAt != nil {
		// A repeat keeps the recovery window; a repeat by anyone but the
		// account records their deletion, which signing in never undoes (P6).
		if !at.self {
			return nil, at.q.AccountDeletionSetDeletedBy(ctx, db.AccountDeletionSetDeletedByParams{UserID: userID, DeletedBy: at.by})
		}
		return nil, nil
	}
	revoked, err := s.revokeCredentialsTx(ctx, at.tx, userID)
	if err != nil {
		return nil, err
	}
	// The invalidate_recovery_grants trigger advances credential_version when
	// deleted_at changes, invalidating every pre-deletion proof atomically.
	if err := at.q.UserSoftDelete(ctx, userID); err != nil {
		return nil, err
	}
	if err := at.st.record(ctx, userEvent(iam.EventUserDeleted, at.userID)); err != nil {
		return nil, err
	}
	return revoked, s.createAccountDeletion(ctx, at.tx, client, userID, at.by)
}

// RestoreUsers restores soft-deleted accounts within their recovery window
// under ACCT(root:users:delete), re-checked against every group role the
// account resumes. Old sessions, device keys and credentials stay revoked.
func (s *Engine) RestoreUsers(ctx context.Context, a auth.Identity, ids []string, opts ...ops.Option) ([]iam.OpResult, error) {
	if err := noOptions("RestoreUsers", opts); err != nil {
		return nil, err
	}
	out := make([]iam.OpResult, 0, len(ids))
	for _, id := range ids {
		err := s.withAccountMutation(ctx, a, id, ident.RootUsersDelete, selfRefused, func(at accountTx) error {
			return s.restoreAccountDeletionOn(ctx, at.tx, a, at.userID, "")
		})
		out = append(out, iam.OpResult{ID: id, Err: err})
	}
	return out, nil
}

// PurgeUsers closes the recovery window of accounts now, soft-deleting live
// ones first: a host operation. The account row goes once the host deletion
// callbacks complete, exactly as at the end of the window.
func (s *Engine) PurgeUsers(ctx context.Context, ids []string, opts ...ops.Option) ([]iam.OpResult, error) {
	if err := noOptions("PurgeUsers", opts); err != nil {
		return nil, err
	}
	client, err := s.deletionRiver()
	if err != nil {
		return nil, err
	}
	out := make([]iam.OpResult, 0, len(ids))
	for _, id := range ids {
		id := strings.TrimSpace(id)
		var revoked []revokedSession
		err := s.withAccountMutation(ctx, iam.SystemIdentity(), id, ident.RootUsersDelete, selfRefused, func(at accountTx) error {
			var err error
			if revoked, err = s.softDeleteTx(ctx, at, client, id); err != nil {
				return err
			}
			deletion, err := at.q.AccountDeletionPurgeNow(ctx, id)
			if errors.Is(err, pgx.ErrNoRows) {
				return nil // already finalizing or purged
			}
			if err != nil {
				return err
			}
			return s.enqueueAccountFinalizer(ctx, at.tx, client, iam.UserDeletion(deletion), false)
		})
		if err == nil {
			s.logRevokedSessions(ctx, id, revoked, string(authflow.SessionRevokeReasonSoftDeleted))
		}
		out = append(out, iam.OpResult{ID: id, Err: err})
	}
	return out, nil
}

// RevokeAccountSessions revokes the account's refresh sessions on every
// account issuer and all its device keys, under
// ACCT(root:users:manage) with peers allowed; an account may revoke its own.
// Issued access tokens expire on their TTL.
func (s *Engine) RevokeAccountSessions(ctx context.Context, a auth.Identity, userID string, opts ...ops.Option) (iam.AccountSessionRevocation, error) {
	if err := noOptions("RevokeAccountSessions", opts); err != nil {
		return iam.AccountSessionRevocation{}, err
	}
	issuers := s.accountIssuers()
	out := iam.AccountSessionRevocation{Issuers: issuers, RevokedSessions: make(map[string]int, len(issuers))}
	for _, issuer := range issuers {
		out.RevokedSessions[issuer] = 0
	}
	reason := string(authflow.SessionRevokeReasonAdminRevokeAll)
	if r := authflow.SessionRevokeReasonFrom(ctx); r != nil {
		reason = *r
	}
	var revoked []revokedSession
	err := s.withAccountMutation(ctx, a, userID, ident.RootUsersManage, selfAllowed|peersAllowed, func(at accountTx) error {
		var err error
		if revoked, err = revokeSessionsTx(ctx, at.q, userID, issuers, nil); err != nil {
			return err
		}
		if err := at.st.record(ctx, userEvent(iam.EventUserSessionsRevoked, at.userID)); err != nil {
			return err
		}
		keys, err := s.revokeAllDeviceKeys(ctx, at.tx, userID)
		if err != nil {
			return err
		}
		unlisted, err := at.q.SessionsCountActiveOutsideIssuers(ctx, db.SessionsCountActiveOutsideIssuersParams{UserID: userID, Issuers: issuers})
		if err != nil {
			return err
		}
		out.RevokedDeviceKeys, out.UnlistedIssuerSessions = int(keys), int(unlisted)
		return nil
	})
	if err != nil {
		return out, err
	}
	for _, r := range revoked {
		out.RevokedSessions[r.Issuer]++
	}
	s.logRevokedSessions(ctx, userID, revoked, reason)
	s.logSessionEvent(ctx, authflow.AuthSessionEvent{Issuer: s.cfg.Token.Issuer, UserID: userID, Event: iam.SessionEventAccountSessionsRevoked, Reason: &reason})
	return out, nil
}

// ResetAccountMFA is the system's recovery for an account that lost its
// second factors (a lost passkey answers passkey_required): it deletes the
// account's passkeys, 2FA factors and backup codes, revokes its device keys
// and its sessions on every account issuer, and tells its address. Roles
// stay: when one needs MFA, or 2FA is Required, the next sign-in enrolls a
// factor: a host operation.
func (s *Engine) ResetAccountMFA(ctx context.Context, userID string, opts ...ops.Option) error {
	if err := noOptions("ResetAccountMFA", opts); err != nil {
		return err
	}
	userID, ok := canonicalUUID(userID)
	if !ok {
		return iam.ErrUserNotFound
	}
	var revoked []revokedSession
	err := s.withAccountMutation(ctx, iam.SystemIdentity(), userID, ident.RootUsersManage, selfRefused, func(at accountTx) error {
		var err error
		revoked, err = s.mutateCredentialsTx(ctx, at.q, userID, nil, func(q *db.Queries, _ db.UserCredentialVersionForUpdateRow) error {
			if err := q.PasskeysDeleteByUser(ctx, userID); err != nil {
				return err
			}
			if err := q.MFADeleteAllFactors(ctx, userID); err != nil {
				return err
			}
			return q.MFASettingsDelete(ctx, userID)
		})
		return err
	})
	if err != nil {
		return err
	}
	s.logRevokedSessions(ctx, userID, revoked, string(authflow.SessionRevokeReasonMFAReset))
	s.notifyMFAReset(ctx, userID)
	return nil
}

// notifyMFAReset is best-effort: the reset is committed, so a delivery failure
// is logged.
func (s *Engine) notifyMFAReset(ctx context.Context, userID string) {
	if s.email == nil {
		return
	}
	u, err := s.getUserByID(ctx, userID)
	if err != nil || u == nil || u.Email == nil {
		return
	}
	if err := s.sendEmail(ctx, iam.EmailMessage{Kind: iam.MessageMFAReset, To: *u.Email, Username: deref(u.Username), Language: s.userLanguage(ctx, userID)}); err != nil {
		stdlog.Printf("[authkit/security] MFA reset notice failed for user %s: %v", userID, err)
	}
}

// RevokeSession revokes one refresh session of the account on this issuer,
// under ACCT(root:users:manage) with peers allowed; an account may revoke its
// own. An unknown or already revoked session is a no-op.
func (s *Engine) RevokeSession(ctx context.Context, a auth.Identity, userID, sessionID string, opts ...ops.Option) error {
	if err := noOptions("RevokeSession", opts); err != nil {
		return err
	}
	if err := requireIdentity(a); err != nil || !isUUID(strings.TrimSpace(sessionID)) {
		return err
	}
	reason := string(authflow.SessionRevokeReasonAdminRevoke)
	if by, target := subjectUserID(a), strings.ToLower(strings.TrimSpace(userID)); by != nil && *by == target {
		reason = string(authflow.SessionRevokeReasonUserRevoke)
	}
	var sid string
	err := s.withAccountMutation(ctx, a, userID, ident.RootUsersManage, selfAllowed|peersAllowed, func(at accountTx) error {
		var err error
		sid, err = at.q.SessionRevokeByIDForUser(ctx, db.SessionRevokeByIDForUserParams{ID: strings.TrimSpace(sessionID), UserID: strings.TrimSpace(userID), Issuer: s.cfg.Token.Issuer})
		if errors.Is(err, pgx.ErrNoRows) {
			return nil
		}
		return err
	})
	if err == nil && sid != "" {
		s.logSessionRevoked(ctx, userID, sid, &reason)
	}
	return err
}
