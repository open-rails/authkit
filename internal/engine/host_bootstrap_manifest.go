package engine

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/internal/authflow"
	"github.com/open-rails/authkit/internal/contact"
	"github.com/open-rails/authkit/internal/db"
	"github.com/open-rails/authkit/internal/errmodel"
	"github.com/open-rails/authkit/internal/password"
	"gopkg.in/yaml.v3"
)

const defaultBootstrapApplyName = "default"

// ParseBootstrapManifestYAML parses and structurally validates a manifest.
func ParseBootstrapManifestYAML(raw []byte) (iam.BootstrapManifest, error) {
	var manifest iam.BootstrapManifest
	dec := yaml.NewDecoder(bytes.NewReader(raw))
	dec.KnownFields(true)
	if err := dec.Decode(&manifest); err != nil {
		return iam.BootstrapManifest{}, err
	}
	if len(manifest.Users) == 0 && len(manifest.RemoteApplications) == 0 {
		return iam.BootstrapManifest{}, errmodel.ErrInvalidBootstrapManifest
	}
	// Parse is env-less and structural-only; the https/private jwks_uri policy
	// is enforced at apply time against the target service's environment (#257).
	if err := validateBootstrapManifest(manifest, true); err != nil {
		return iam.BootstrapManifest{}, err
	}
	return manifest, nil
}

// ApplyBootstrapManifest applies seed data and its StartupOnly receipt in one
// authority transaction, under the operator. It never adopts an account
// through a username, an alias or an unverified contact, and never changes an
// existing account's identity or marks its contacts verified (see
// iam.BootstrapManifestUser). Role changes run the credential sweep.
func (s *Engine) ApplyBootstrapManifest(ctx context.Context, manifest iam.BootstrapManifest, opts iam.BootstrapOptions) (iam.BootstrapResult, error) {
	if err := s.requirePG(); err != nil {
		return iam.BootstrapResult{}, err
	}
	if err := validateBootstrapManifest(manifest, s.cfg.Applications.AllowPrivateNetworkJWKS); err != nil {
		return iam.BootstrapResult{}, err
	}
	schema := s.groupSchemaOrDefault()
	checkRole := func(raw iam.Role) error {
		role := normalizeRootRoleSlug(raw)
		if role != "" && !s.validRoleForPersona(schema, iam.RootPersona, role) {
			return fmt.Errorf("bootstrap root role %q: %w", role, iam.ErrRoleNotAssignable)
		}
		return nil
	}
	accounts := make([]newAccount, len(manifest.Users))
	for i, user := range manifest.Users {
		if user.Password != nil && strings.TrimSpace(user.Password.Plaintext) != "" {
			if err := s.ValidatePassword(strings.TrimSpace(user.Password.Plaintext), user.Username, user.Email); err != nil {
				return iam.BootstrapResult{}, err
			}
		}
		accounts[i] = bootstrapAccount(user)
		if _, _, _, _, _, _, _, err := s.normalizeImportUserInput(accounts[i]); err != nil {
			return iam.BootstrapResult{}, err
		}
		if err := checkRole(user.RootRole); err != nil {
			return iam.BootstrapResult{}, err
		}
	}
	for _, app := range manifest.RemoteApplications {
		if err := checkRole(app.RootRole); err != nil {
			return iam.BootstrapResult{}, err
		}
	}
	if opts.DryRun {
		result := iam.BootstrapResult{DryRun: true, UsersCreated: len(manifest.Users), RemoteApplications: len(manifest.RemoteApplications)}
		for _, user := range manifest.Users {
			result.PasswordsSet += boolToInt(user.Password != nil)
			result.RootRoleAssignments += boolToInt(normalizeRootRoleSlug(user.RootRole) != "")
		}
		for _, app := range manifest.RemoteApplications {
			result.RemoteApplicationRootRoles += boolToInt(normalizeRootRoleSlug(app.RootRole) != "")
		}
		return result, nil
	}
	// Hash before taking locks. Equality is checked against the stored
	// credential under its account lock.
	passwords := make([]db.UserPasswordUpsertParams, len(manifest.Users))
	for i, user := range manifest.Users {
		if user.Password != nil {
			var err error
			if passwords[i], err = prepareBootstrapPassword(*user.Password); err != nil {
				return iam.BootstrapResult{}, err
			}
		}
	}
	type revocation struct {
		userID   string
		sessions []revokedSession
	}
	var result iam.BootstrapResult
	var revocations []revocation
	err := s.withAuthorityMutation(ctx, iam.OperatorActor(), func(st *permissionGroupStore) error {
		result, revocations = iam.BootstrapResult{}, nil
		if opts.StartupOnly {
			already, err := s.claimBootstrapApply(ctx, st.q, opts.Name)
			if err != nil || already {
				result.AlreadyApplied = already
				return err
			}
		}
		rootID, err := s.rootGroup(ctx, st)
		if err != nil {
			return err
		}
		for _, app := range manifest.RemoteApplications {
			if err := s.applyBootstrapRemoteApplication(ctx, st, rootID, app); err != nil {
				return err
			}
			result.RemoteApplications++
			result.RemoteApplicationRootRoles += boolToInt(normalizeRootRoleSlug(app.RootRole) != "")
		}
		owners, err := st.OwnerCount(ctx, rootID)
		if err != nil {
			return err
		}
		for i, user := range manifest.Users {
			id, sessions, err := s.applyBootstrapUser(ctx, st, rootID, owners, user, accounts[i], passwords[i], &result)
			if err != nil {
				return err
			}
			if len(sessions) > 0 {
				revocations = append(revocations, revocation{id, sessions})
			}
		}
		return nil
	})
	if err != nil {
		return iam.BootstrapResult{}, err
	}
	for _, r := range revocations {
		s.logRevokedSessions(ctx, r.userID, r.sessions, string(authflow.SessionRevokeReasonAdminSetPassword))
	}
	s.logRBACDrift(ctx)
	return result, nil
}

// bootstrapMatch is the existing account a manifest user names, if any.
type bootstrapMatch struct {
	id         string
	bound      bool // found through a contact verified on the account
	deleted    bool
	channel    string // email, phone or username: how it was found
	identifier string
}

// refusal is the error for an apply that would write to an account it may
// not adopt.
func (m bootstrapMatch) refusal(username string) error {
	if m.deleted {
		return fmt.Errorf("bootstrap user %q: the account with its %s is deleted: %w", username, m.channel, iam.ErrUserNotFound)
	}
	reason := "contact_unproven"
	if m.channel == "username" {
		reason = "no_contact"
	}
	return fmt.Errorf("bootstrap user %q: an existing account is used only through a verified email or phone the manifest names: %w", username,
		errmodel.E(errmodel.CodeContactNotVerified, errmodel.WithMetadata(map[string]any{"identifier": m.identifier, "channel": m.channel, "reason": reason})))
}

// findBootstrapAccount locks the account the user's email or phone names.
// With neither, it looks up the canonical username only, which never binds;
// an alias is never followed.
func (s *Engine) findBootstrapAccount(ctx context.Context, q db.DBTX, user iam.BootstrapManifestUser) (bootstrapMatch, error) {
	var m bootstrapMatch
	find := func(channel, identifier, sql string) error {
		var id string
		var verified, deleted bool
		err := q.QueryRow(ctx, sql, identifier).Scan(&id, &verified, &deleted)
		if errors.Is(err, pgx.ErrNoRows) {
			return nil
		}
		if err != nil {
			return err
		}
		if m.id != "" && m.id != id {
			return fmt.Errorf("bootstrap user %q: its email and phone belong to different accounts: %w", user.Username, iam.ErrPhoneInUse)
		}
		if m.id == "" {
			m.channel, m.identifier = channel, identifier
		}
		m.id, m.deleted, m.bound = id, deleted, m.bound || verified
		return nil
	}
	email, phone := strings.TrimSpace(user.Email), strings.TrimSpace(user.Phone)
	if email != "" {
		if err := find("email", contact.NormalizeEmail(email), `SELECT id::text, email_verified, deleted_at IS NOT NULL FROM users WHERE email=$1::text::public.citext FOR UPDATE`); err != nil {
			return m, err
		}
	}
	if phone != "" {
		if err := find("phone", contact.NormalizePhone(phone), `SELECT id::text, phone_verified, deleted_at IS NOT NULL FROM users WHERE phone_number=$1 FOR UPDATE`); err != nil {
			return m, err
		}
	}
	if email != "" || phone != "" {
		return m, nil
	}
	username := strings.TrimSpace(user.Username)
	err := q.QueryRow(ctx, `SELECT u.id::text, u.deleted_at IS NOT NULL FROM name_claims c JOIN users u ON u.id=c.owner_id
 WHERE c.owner_kind='user' AND c.persona='' AND c.name=lower($1) AND c.canonical FOR UPDATE OF u`, username).Scan(&m.id, &m.deleted)
	if errors.Is(err, pgx.ErrNoRows) {
		return bootstrapMatch{}, nil
	}
	m.channel, m.identifier = "username", username
	return m, err
}

// applyBootstrapUser applies one manifest user and returns its account id and
// any sessions a password change revoked. A new account is created as
// declared and gets its role without an MFA check (it cannot be enrolled yet;
// its first session must enroll). An existing account gets only its password
// (when enforced) and root role, and only when bound; an unbound one is
// refused unless nothing would change.
func (s *Engine) applyBootstrapUser(ctx context.Context, st *permissionGroupStore, rootID string, owners int, user iam.BootstrapManifestUser, acct newAccount, prepared db.UserPasswordUpsertParams, result *iam.BootstrapResult) (string, []revokedSession, error) {
	q := db.New(st.q)
	role := normalizeRootRoleSlug(user.RootRole)
	// Existing owners are never displaced by a seed-if-absent owner entry.
	seedsRole := role != "" && (role != iam.OwnerRole || owners == 0)
	if role != "" {
		result.RootRoleAssignments++
	}
	m, err := s.findBootstrapAccount(ctx, st.q, user)
	if err != nil {
		return "", nil, err
	}
	created := m.id == ""
	current := iam.Role("")
	if created {
		u, err := s.importUser(ctx, q, acct)
		if err != nil {
			return "", nil, fmt.Errorf("bootstrap user %q: %w", user.Username, mapUserUniqueViolation(err))
		}
		m.id = u.ID
		result.UsersCreated++
		if err := st.record(ctx, userEvent(iam.EventUserRegistered, m.id)); err != nil {
			return "", nil, err
		}
	} else {
		if current, err = st.directRole(ctx, rootID, iam.UserSubject(m.id)); err != nil {
			return "", nil, err
		}
		enforce := user.Password != nil && user.Password.Enforce
		if (!m.bound || m.deleted) && (enforce || seedsRole && current != role) {
			return "", nil, m.refusal(user.Username)
		}
		result.UsersMatched++
	}
	subject := iam.UserSubject(m.id)
	var revoked []revokedSession
	if user.Password != nil {
		if created || user.Password.Enforce {
			set, r, err := s.applyBootstrapUserPassword(ctx, q, m.id, *user.Password, prepared)
			if err != nil {
				return "", nil, err
			}
			result.PasswordsSet += boolToInt(set)
			result.PasswordsKept += boolToInt(!set)
			revoked = r
		} else {
			result.PasswordsKept++
		}
	}
	if !seedsRole || current == role {
		return m.id, revoked, nil
	}
	if err := s.requireDefinedGroupRole(ctx, st, rootID, iam.RootPersona, role); err != nil {
		return "", nil, err
	}
	if current != "" {
		if err := s.refuseOwnerLoss(ctx, st, rootID, subject); err != nil {
			return "", nil, err
		}
	}
	if !created {
		if err := s.requireMFAForRoleAssignment(ctx, st.q, rootID, iam.RootPersona, subject, role); err != nil {
			return "", nil, err
		}
	}
	return m.id, revoked, st.AssignRole(ctx, rootID, subject, role)
}

func (s *Engine) bootstrapApplyName(name string) string {
	if name = strings.TrimSpace(name); name != "" {
		return name
	}
	return defaultBootstrapApplyName
}

// claimBootstrapApply decides whether a StartupOnly apply may run (#259).
// The refusal protects an authority graph nobody recorded creating, so its
// scope is the whole claim table, not one name: any recorded claim means the
// graph is accounted for and a new name records itself as already applied
// instead of refusing. Only a non-empty graph with an EMPTY claim table is
// refused.
func (s *Engine) claimBootstrapApply(ctx context.Context, q db.DBTX, name string) (already bool, err error) {
	name = s.bootstrapApplyName(name)
	var nameClaimed, anyClaimed, graphEmpty bool
	if err := q.QueryRow(ctx, `
  SELECT
   EXISTS (SELECT 1 FROM bootstrap_applies WHERE name = $1),
   EXISTS (SELECT 1 FROM bootstrap_applies),
   NOT EXISTS (SELECT 1 FROM users WHERE deleted_at IS NULL)
   AND NOT EXISTS (SELECT 1 FROM remote_applications)
 `, name).Scan(&nameClaimed, &anyClaimed, &graphEmpty); err != nil {
		return false, err
	}
	if nameClaimed {
		return true, nil
	}
	if !anyClaimed && !graphEmpty {
		return false, errmodel.ErrBootstrapDatabaseNotEmpty
	}
	_, err = q.Exec(ctx, `INSERT INTO bootstrap_applies (name) VALUES ($1)`, name)
	return anyClaimed, err
}

func validateBootstrapManifest(manifest iam.BootstrapManifest, allowInsecureJWKS bool) error {
	for _, user := range manifest.Users {
		if strings.TrimSpace(user.Username) == "" {
			return errmodel.ErrInvalidBootstrapManifest
		}
		if !user.Banned && (user.BannedUntil != nil || strings.TrimSpace(user.BanReason) != "") {
			return errmodel.ErrInvalidBootstrapManifest
		}
		if user.Password != nil {
			if err := validateBootstrapUserPassword(*user.Password); err != nil {
				return err
			}
		}
	}
	for _, app := range manifest.RemoteApplications {
		if strings.TrimSpace(app.Slug) == "" || strings.TrimSpace(app.Issuer) == "" || app.Enabled == nil {
			return errmodel.ErrInvalidBootstrapManifest
		}
		if _, err := normalizeRemoteAppTrustSource(app.JWKSURI, "", app.PublicKeys, trustSourcePolicy{AllowPrivateNetworkJWKS: allowInsecureJWKS}); err != nil {
			return err
		}
	}
	return nil
}

func (s *Engine) applyBootstrapRemoteApplication(ctx context.Context, st *permissionGroupStore, rootID string, app iam.BootstrapManifestRemoteApplication) error {
	ra, err := s.upsertRemoteApplication(ctx, st, iam.RemoteApplication{
		Slug:              strings.TrimSpace(app.Slug),
		PermissionGroupID: rootID,
		Issuer:            strings.TrimSpace(app.Issuer),
		JWKSURI:           strings.TrimSpace(app.JWKSURI),
		PublicKeys:        app.PublicKeys,
		Enabled:           *app.Enabled,
	})
	if err != nil {
		return err
	}
	role := normalizeRootRoleSlug(app.RootRole)
	if role == "" {
		return nil
	}
	subject := iam.RemoteApplicationSubject(ra.ID)
	// An application can present no second factor, so no path hands it a
	// role that needs one.
	if err := s.requireMFAForRoleAssignment(ctx, st.q, rootID, iam.RootPersona, subject, role); err != nil {
		return err
	}
	if role != iam.OwnerRole {
		if err := s.refuseOwnerLoss(ctx, st, rootID, subject); err != nil {
			return err
		}
	}
	return st.AssignRole(ctx, rootID, subject, role)
}

func validateBootstrapUserPassword(p iam.BootstrapUserPassword) error {
	modes := 0
	if strings.TrimSpace(p.Plaintext) != "" {
		modes++
	}
	if strings.TrimSpace(p.Hash) != "" || strings.TrimSpace(p.HashAlgo) != "" {
		modes++
		if strings.TrimSpace(p.Hash) == "" || strings.TrimSpace(p.HashAlgo) == "" {
			return errmodel.ErrInvalidBootstrapManifest
		}
		if err := validatePasswordHashForStorage(strings.TrimSpace(p.Hash), strings.TrimSpace(p.HashAlgo)); err != nil {
			return fmt.Errorf("%w: %w", errmodel.ErrInvalidBootstrapManifest, err)
		}
	}
	if p.ResetRequired {
		modes++
	}
	if modes != 1 {
		return errmodel.ErrInvalidBootstrapManifest
	}
	// enforce-as-desired-state is incompatible with reset_required (#89): a
	// reset sentinel re-applied every reconcile would force a reset on every run.
	if p.Enforce && (p.ResetRequired || strings.TrimSpace(p.HashAlgo) == iam.HashAlgoLegacyResetRequired) {
		return errmodel.ErrInvalidBootstrapManifest
	}
	return nil
}

// bootstrapAccount is the account a manifest user creates.
func bootstrapAccount(user iam.BootstrapManifestUser) newAccount {
	acct := newAccount{
		Email:         user.Email,
		PhoneNumber:   user.Phone,
		Username:      user.Username,
		EmailVerified: user.EmailVerified,
		PhoneVerified: user.PhoneVerified,
		Metadata:      user.Metadata,
	}
	if user.Banned {
		now := time.Now().UTC()
		acct.BannedAt, acct.BannedUntil, acct.BanReason = &now, user.BannedUntil, nullable(strings.TrimSpace(user.BanReason))
	}
	return acct
}

func prepareBootstrapPassword(p iam.BootstrapUserPassword) (out db.UserPasswordUpsertParams, err error) {
	if plaintext := strings.TrimSpace(p.Plaintext); plaintext != "" {
		out.PasswordHash, err = password.HashArgon2id(plaintext)
		out.HashAlgo = "argon2id"
	} else if p.ResetRequired {
		out.PasswordHash, out.HashAlgo = "reset-required", iam.HashAlgoLegacyResetRequired
	} else {
		out.PasswordHash, out.HashAlgo = strings.TrimSpace(p.Hash), strings.TrimSpace(p.HashAlgo)
	}
	return out, err
}

func (s *Engine) applyBootstrapUserPassword(ctx context.Context, q *db.Queries, userID string, p iam.BootstrapUserPassword, prepared db.UserPasswordUpsertParams) (bool, []revokedSession, error) {
	// Use the same lock order as every credential mutation, including the no-op
	// comparison, so another password change cannot slip between read and write.
	if _, err := q.UserCredentialVersionForUpdate(ctx, userID); err != nil {
		return false, nil, err
	}
	if plaintext := strings.TrimSpace(p.Plaintext); plaintext != "" {
		row, err := q.UserPasswordRow(ctx, userID)
		if err != nil && !errors.Is(err, pgx.ErrNoRows) {
			return false, nil, err
		}
		if err == nil && verifyPasswordHash(row.PasswordHash, row.HashAlgo, plaintext) == nil {
			return false, nil, nil
		}
	}
	prepared.UserID = userID
	revoked, err := s.mutateCredentialsTx(ctx, q, userID, nil, func(q *db.Queries, _ db.UserCredentialVersionForUpdateRow) error {
		return q.UserPasswordUpsert(ctx, prepared)
	})
	return err == nil, revoked, err
}

func boolToInt(v bool) int {
	if v {
		return 1
	}
	return 0
}
