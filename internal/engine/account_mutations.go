package engine

import (
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
	"github.com/open-rails/authkit/internal/password"
)

// Account mutations. Every one takes an actor and runs in one authority
// transaction: rule ACCT(p) (requireAccount: CAP p on root plus coverage of
// the target's grants in root and every group it holds a role in), or the
// operation's self rule, then the change, then a sweep of the target's
// credentials (revokeCredentialsOf), so a key or link never outlives the
// account authority that issued it.

type selfRule uint8

const (
	selfRefused selfRule = iota // acting on one's own account is ErrCannotTargetSelf
	selfAllowed                 // one's own account needs only a live actor
)

// accountTx is the transaction an account mutation applies its change in.
type accountTx struct {
	tx     pgx.Tx
	q      *db.Queries
	st     *permissionGroupStore // records events of the acting actor
	userID string                // the target, canonical
	system bool
	self   bool
	by     *string // the acting user; nil for the system
}

func (s *Engine) withAccountMutation(ctx context.Context, a iam.Actor, userID string, p iam.Perm, self selfRule, apply func(at accountTx) error) error {
	if err := requireActor(a); err != nil {
		return err
	}
	if err := s.requirePG(); err != nil {
		return err
	}
	userID, ok := canonicalUUID(userID)
	if !ok {
		return iam.ErrUserNotFound
	}
	tx, err := s.beginAuthorityTransaction(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	st := s.groupStoreFor(tx)
	st.actor = a
	if err := s.lockAuthority(ctx, tx); err != nil {
		return err
	}
	at := accountTx{tx: tx, q: s.qtx(tx), st: st, userID: userID, system: a.Kind() == iam.ActorSystem, by: actorUserID(a)}
	at.self = at.by != nil && *at.by == userID
	switch {
	case at.self && self == selfRefused:
		return iam.ErrCannotTargetSelf
	case at.self:
		rootID, err := s.rootGroup(ctx, st)
		if err != nil {
			return err
		}
		if _, err := s.actorAuthority(ctx, st, a, groupTarget{ID: rootID, Persona: iam.RootPersona}); err != nil {
			return err
		}
	default:
		if err := s.requireAccount(ctx, st, a, userID, p); err != nil {
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

// actorUserID is the account behind a, in canonical form, for self rules and
// audit columns; nil for the system and machines.
func actorUserID(a iam.Actor) *string {
	if a.Kind() != iam.ActorUser {
		return nil
	}
	id := a.ID()
	if canonical, ok := canonicalUUID(id); ok {
		id = canonical
	}
	return &id
}

// CreateUser creates a native account: a host operation.
func (s *Engine) CreateUser(ctx context.Context, n iam.NewUser) (iam.User, error) {
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
	if err := s.cfg.Username.ValidateImport(username); err != nil {
		return iam.User{}, err
	}
	var hash string
	if n.Password != "" {
		if err := s.ValidatePassword(n.Password, username, deref(email)); err != nil {
			return iam.User{}, err
		}
		var err error
		if hash, err = password.HashArgon2id(n.Password); err != nil {
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
	tx, err := s.pg.Begin(ctx)
	if err != nil {
		return iam.User{}, err
	}
	defer tx.Rollback(ctx)
	now := time.Now().UTC()
	err = s.qtx(tx).UserImportInsert(ctx, db.UserImportInsertParams{
		ID: userID, Email: email, PhoneNumber: phone, Username: &username, AtTime: s.namingNow(),
		EmailVerified: n.EmailVerified, PhoneVerified: n.PhoneVerified, Metadata: []byte(`{}`), CreatedAt: now, UpdatedAt: now,
	})
	if err != nil {
		return iam.User{}, mapUserUniqueViolation(err)
	}
	if hash != "" {
		if err := s.qtx(tx).UserPasswordUpsert(ctx, db.UserPasswordUpsertParams{UserID: userID, PasswordHash: hash, HashAlgo: "argon2id"}); err != nil {
			return iam.User{}, err
		}
	}
	if err := s.emitEvents(ctx, tx, iam.SystemActor(), userEvent(iam.EventUserRegistered, userID)); err != nil {
		return iam.User{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return iam.User{}, err
	}
	return s.User(ctx, iam.UserByID(userID))
}

// selfEditable are the UserUpdate fields an account may change on itself.
func selfEditable(u iam.UserUpdate) bool {
	return u.Email == nil && u.Phone == nil && u.Password == nil && u.EmailVerified == nil && u.PhoneVerified == nil && u.PasswordHash == nil
}

// UpdateUser changes an account under ACCT(root:users:manage). An account may
// change its own Username, AvatarURL and PreferredLanguage (rename policy
// applies); Password, PasswordHash and the verified flags are system-only
// (staff send a reset to the proven address instead). Setting a verified flag
// is the proof transition: on an account with no proven contact it first
// retires every pre-proof credential. A contact change never leaves an
// account with a second factor or MFA-required roles without a proven
// contact, since the next proof would retire its MFA, and never moves its
// email factor, which stays bound to the address it was proven for. Nothing
// is sent to the new address.
func (s *Engine) UpdateUser(ctx context.Context, a iam.Actor, userID string, u iam.UserUpdate) (iam.User, error) {
	if a.Kind() != iam.ActorSystem && (u.EmailVerified != nil || u.PhoneVerified != nil || u.Password != nil || u.PasswordHash != nil) {
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
	err := s.withAccountMutation(ctx, a, userID, iam.PermRootUsersManage, self, func(at accountTx) error {
		before, err := readAccountIdentity(ctx, at.tx, at.userID)
		if err != nil {
			return err
		}
		if revoked, err = s.applyUserUpdate(ctx, at, strings.TrimSpace(userID), u); err != nil {
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
	return s.User(ctx, iam.UserByID(userID), iam.IncludeDeleted())
}

// userUpdateRevocations are the sessions an update revoked, by cause.
type userUpdateRevocations struct{ proven, password []revokedSession }

func (s *Engine) applyUserUpdate(ctx context.Context, at accountTx, userID string, u iam.UserUpdate) (userUpdateRevocations, error) {
	var revoked userUpdateRevocations
	before, err := contactStateForUpdate(ctx, at.tx, userID)
	if err != nil {
		return revoked, err
	}
	if (u.EmailVerified != nil && *u.EmailVerified) || (u.PhoneVerified != nil && *u.PhoneVerified) {
		if revoked.proven, err = s.retirePreProofCredentials(ctx, at.tx, userID, nil); err != nil {
			return revoked, err
		}
	}
	if u.Username != nil {
		authority := normalRename
		if at.system {
			authority = importRename
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
		if _, err := at.tx.Exec(ctx, `UPDATE users SET email=$2, email_verified=false, updated_at=now() WHERE id=$1::uuid AND email IS DISTINCT FROM $2::text::public.citext`, userID, email); err != nil {
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
		if _, err := at.tx.Exec(ctx, `UPDATE users SET phone_number=$2, phone_verified=false, updated_at=now() WHERE id=$1::uuid AND phone_number IS DISTINCT FROM $2`, userID, phone); err != nil {
			return revoked, mapUserUniqueViolation(err)
		}
	}
	for _, flag := range []struct {
		set    *bool
		column string
	}{{u.EmailVerified, "email"}, {u.PhoneVerified, "phone_number"}} {
		if flag.set == nil {
			continue
		}
		verified := "email_verified"
		if flag.column == "phone_number" {
			verified = "phone_verified"
		}
		tag, err := at.tx.Exec(ctx, `UPDATE users SET `+verified+`=$2, updated_at=now() WHERE id=$1::uuid AND (NOT $2 OR `+flag.column+` IS NOT NULL)`, userID, *flag.set)
		if err != nil {
			return revoked, err
		}
		if tag.RowsAffected() == 0 {
			return revoked, errmodel.E(errmodel.CodeInvalidRequest, errmodel.WithParam(verified))
		}
	}
	if u.Email != nil || u.Phone != nil || u.EmailVerified != nil || u.PhoneVerified != nil {
		if err := s.keepMFAHolderProven(ctx, at.tx, userID, before); err != nil {
			return revoked, err
		}
	}
	if u.AvatarURL != nil {
		avatar, err := normalizeAvatarURL(*u.AvatarURL)
		if err != nil {
			return revoked, err
		}
		if _, err := at.tx.Exec(ctx, `UPDATE users SET avatar_url=$2, updated_at=now() WHERE id=$1::uuid`, userID, avatar); err != nil {
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
		if _, err := at.tx.Exec(ctx, `UPDATE users SET preferred_language=$2, updated_at=now() WHERE id=$1::uuid`, userID, language); err != nil {
			return revoked, err
		}
	}
	if u.Password != nil || u.PasswordHash != nil {
		hash, algo, err := s.passwordForUpdate(ctx, at.tx, userID, u)
		if err != nil {
			return revoked, err
		}
		revoked.password, err = s.mutateCredentialsTx(ctx, at.q, userID, nil, func(q *db.Queries, _ db.UserCredentialVersionForUpdateRow) error {
			return q.UserPasswordUpsert(ctx, db.UserPasswordUpsertParams{UserID: userID, PasswordHash: hash, HashAlgo: algo})
		})
		if err != nil {
			return revoked, err
		}
	}
	return revoked, nil
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
	enrolled, err := userHasEnabledMFA(ctx, tx, userID)
	if err != nil {
		return err
	}
	if !enrolled {
		holds, err := s.userHoldsMFARequiredRole(ctx, tx, userID)
		if err != nil || !holds {
			return err
		}
	}
	return contactVerificationRequired(after)
}

// passwordForUpdate validates a new password against the policy and the
// account's current identifiers, or an imported hash, and returns what to store.
func (s *Engine) passwordForUpdate(ctx context.Context, tx pgx.Tx, userID string, u iam.UserUpdate) (hash, algo string, err error) {
	if u.PasswordHash != nil {
		hash, algo = strings.TrimSpace(u.PasswordHash.Hash), strings.TrimSpace(u.PasswordHash.Algo)
		return hash, algo, validatePasswordHashForStorage(hash, algo)
	}
	var username, email *string
	if err := tx.QueryRow(ctx, `SELECT username::text, email::text FROM users WHERE id=$1::uuid`, userID).Scan(&username, &email); err != nil {
		return "", "", err
	}
	if err := s.ValidatePassword(*u.Password, deref(username), deref(email)); err != nil {
		return "", "", err
	}
	hash, err = password.HashArgon2id(*u.Password)
	return hash, "argon2id", err
}

// maxAvatarURLLen caps the stored avatar URL or key: a sanity bound, not
// format validation, since hosts may store opaque object keys.
const maxAvatarURLLen = 2048

func normalizeAvatarURL(v string) (*string, error) {
	v = strings.TrimSpace(v)
	switch {
	case v == "":
		return nil, nil
	case len(v) > maxAvatarURLLen || strings.ContainsAny(v, "\n\r"):
		return nil, errmodel.ErrAvatarURLInvalid
	}
	return &v, nil
}

// reservedMetadataKeys are the metadata keys AuthKit owns.
var reservedMetadataKeys = []string{"reserved"}

// PatchUserMetadata merges patch into the account's application-owned
// metadata under ACCT(root:users:manage); a nil value deletes its key. Keys
// AuthKit owns are refused.
func (s *Engine) PatchUserMetadata(ctx context.Context, a iam.Actor, userID string, patch map[string]any) error {
	set, drop := map[string]any{}, []string{}
	for k, v := range patch {
		for _, reserved := range reservedMetadataKeys {
			if k == reserved {
				return errmodel.E(errmodel.CodeInvalidRequest, errmodel.WithParam(k))
			}
		}
		if v == nil {
			drop = append(drop, k)
			continue
		}
		set[k] = v
	}
	raw, err := json.Marshal(set)
	if err != nil {
		return err
	}
	return s.withAccountMutation(ctx, a, userID, iam.PermRootUsersManage, selfRefused, func(at accountTx) error {
		if len(patch) == 0 {
			return nil
		}
		_, err := at.tx.Exec(ctx, `UPDATE users SET metadata=(COALESCE(metadata,'{}'::jsonb) || $2::jsonb) - $3::text[], updated_at=now() WHERE id=$1::uuid`, userID, raw, drop)
		return err
	})
}

// Ban bans an account under ACCT(root:users:ban) and revokes its sessions,
// device keys and every credential it issued, in one transaction. Nobody bans
// themselves, and the last usable owner of a group cannot be banned.
func (s *Engine) Ban(ctx context.Context, a iam.Actor, userID string, b iam.Ban) error {
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
	err := s.withAccountMutation(ctx, a, userID, iam.PermRootUsersBan, selfRefused, func(at accountTx) error {
		if b.KeepExisting {
			var inForce bool
			if err := at.tx.QueryRow(ctx, `SELECT banned_at IS NOT NULL AND (banned_until IS NULL OR banned_until>now()) FROM users WHERE id=$1::uuid`, userID).Scan(&inForce); err != nil {
				return err
			}
			if inForce {
				return nil
			}
		}
		if err := s.refuseSubjectOwnerLoss(ctx, at.st, iam.UserSubject(userID)); err != nil {
			return err
		}
		if err := at.q.UserBan(ctx, db.UserBanParams{ID: userID, BannedAt: &now, BannedUntil: until, BanReason: reason, BannedBy: actorUserID(a)}); err != nil {
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
func (s *Engine) Unban(ctx context.Context, a iam.Actor, userID string) error {
	return s.withAccountMutation(ctx, a, userID, iam.PermRootUsersBan, selfRefused, func(at accountTx) error {
		var inForce bool
		if err := at.tx.QueryRow(ctx, `SELECT banned_at IS NOT NULL AND (banned_until IS NULL OR banned_until>now()) FROM users WHERE id=$1::uuid`, at.userID).Scan(&inForce); err != nil {
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
func (s *Engine) DeleteUsers(ctx context.Context, a iam.Actor, ids []string) ([]iam.OpResult, error) {
	out := make([]iam.OpResult, 0, len(ids))
	for _, id := range ids {
		out = append(out, iam.OpResult{ID: id, Err: s.deleteUser(ctx, a, id)})
	}
	return out, nil
}

func (s *Engine) deleteUser(ctx context.Context, a iam.Actor, userID string) error {
	client, err := s.deletionRiver()
	if err != nil {
		return err
	}
	var revoked []revokedSession
	err = s.withAccountMutation(ctx, a, userID, iam.PermRootUsersDelete, selfAllowed, func(at accountTx) error {
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
			_, err := at.tx.Exec(ctx, `UPDATE account_deletions SET deleted_by=$2::uuid WHERE user_id=$1::uuid AND state='deleted'`, userID, at.by)
			return nil, err
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
func (s *Engine) RestoreUsers(ctx context.Context, a iam.Actor, ids []string) ([]iam.OpResult, error) {
	out := make([]iam.OpResult, 0, len(ids))
	for _, id := range ids {
		err := s.withAccountMutation(ctx, a, id, iam.PermRootUsersDelete, selfRefused, func(at accountTx) error {
			return s.restoreAccountDeletionOn(ctx, at.tx, a, at.userID, "")
		})
		out = append(out, iam.OpResult{ID: id, Err: err})
	}
	return out, nil
}

// PurgeUsers closes the recovery window of accounts now, soft-deleting live
// ones first: a host operation. The account row goes once the host deletion
// callbacks complete, exactly as at the end of the window.
func (s *Engine) PurgeUsers(ctx context.Context, ids []string) ([]iam.OpResult, error) {
	client, err := s.deletionRiver()
	if err != nil {
		return nil, err
	}
	out := make([]iam.OpResult, 0, len(ids))
	for _, id := range ids {
		id := strings.TrimSpace(id)
		var revoked []revokedSession
		err := s.withAccountMutation(ctx, iam.SystemActor(), id, iam.PermRootUsersDelete, selfRefused, func(at accountTx) error {
			var err error
			if revoked, err = s.softDeleteTx(ctx, at, client, id); err != nil {
				return err
			}
			var deletion iam.UserDeletion
			err = at.tx.QueryRow(ctx, `UPDATE account_deletions SET purge_at=statement_timestamp()
 WHERE user_id=$1::uuid AND state='deleted' RETURNING id::text, user_id::text, deleted_at, purge_at`, id).Scan(&deletion.ID, &deletion.UserID, &deletion.DeletedAt, &deletion.PurgeAt)
			if errors.Is(err, pgx.ErrNoRows) {
				return nil // already finalizing or purged
			}
			if err != nil {
				return err
			}
			return s.enqueueAccountFinalizer(ctx, at.tx, client, deletion, false)
		})
		if err == nil {
			s.logRevokedSessions(ctx, id, revoked, string(authflow.SessionRevokeReasonSoftDeleted))
		}
		out = append(out, iam.OpResult{ID: id, Err: err})
	}
	return out, nil
}

// RevokeAccountSessions revokes the account's refresh sessions on every
// account issuer and all its device keys, under ACCT(root:users:manage); an
// account may revoke its own. Issued access tokens expire on their TTL.
func (s *Engine) RevokeAccountSessions(ctx context.Context, a iam.Actor, userID string) (iam.AccountSessionRevocation, error) {
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
	err := s.withAccountMutation(ctx, a, userID, iam.PermRootUsersManage, selfAllowed, func(at accountTx) error {
		var err error
		if revoked, err = revokeSessionsTx(ctx, at.q, userID, issuers, nil); err != nil {
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
func (s *Engine) ResetAccountMFA(ctx context.Context, userID string) error {
	userID, ok := canonicalUUID(userID)
	if !ok {
		return iam.ErrUserNotFound
	}
	var revoked []revokedSession
	err := s.withAccountMutation(ctx, iam.SystemActor(), userID, iam.PermRootUsersManage, selfRefused, func(at accountTx) error {
		var err error
		revoked, err = s.mutateCredentialsTx(ctx, at.q, userID, nil, func(q *db.Queries, _ db.UserCredentialVersionForUpdateRow) error {
			if _, err := at.tx.Exec(ctx, `UPDATE user_passkeys SET deleted_at=now() WHERE user_id=$1::uuid AND deleted_at IS NULL`, userID); err != nil {
				return err
			}
			if err := q.MFADeleteAllFactors(ctx, userID); err != nil {
				return err
			}
			_, err := at.tx.Exec(ctx, `DELETE FROM mfa_settings WHERE user_id=$1::uuid`, userID)
			return err
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
	sendCtx := s.contextWithUserPreferredLanguage(ctx, userID)
	if err := s.withSendTimeout(sendCtx, func(c context.Context) error {
		return s.email.SendMFAReset(c, *u.Email, deref(u.Username))
	}); err != nil {
		stdlog.Printf("[authkit/security] MFA reset notice failed for user %s: %v", userID, err)
	}
}

// RevokeSession revokes one refresh session of the account on this issuer,
// under ACCT(root:users:manage); an account may revoke its own. An unknown
// or already revoked session is a no-op.
func (s *Engine) RevokeSession(ctx context.Context, a iam.Actor, userID, sessionID string) error {
	if err := requireActor(a); err != nil || !isUUID(strings.TrimSpace(sessionID)) {
		return err
	}
	reason := string(authflow.SessionRevokeReasonAdminRevoke)
	if by, target := actorUserID(a), strings.ToLower(strings.TrimSpace(userID)); by != nil && *by == target {
		reason = string(authflow.SessionRevokeReasonUserRevoke)
	}
	var sid string
	err := s.withAccountMutation(ctx, a, userID, iam.PermRootUsersManage, selfAllowed, func(at accountTx) error {
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
