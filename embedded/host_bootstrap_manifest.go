package embedded

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	authkit "github.com/open-rails/authkit"

	"github.com/jackc/pgx/v5"
	"github.com/open-rails/authkit/internal/db"
	"github.com/open-rails/authkit/password"
	"gopkg.in/yaml.v3"
)

const DefaultBootstrapManifestPath = "/etc/authkit/bootstrap.yaml"

var (
	ErrInvalidBootstrapManifest  = authkit.ErrInvalidBootstrapManifest
	ErrBootstrapDatabaseNotEmpty = authkit.ErrBootstrapDatabaseNotEmpty
)

const defaultBootstrapApplyName = "default"

// BootstrapManifest is AuthKit's first-class closed-deployment seed manifest.
// It creates/updates initial users and assigns root roles after the host app has
// already configured AuthKit's RBAC schema in code.
//
// Operator authority is a role assignment in the singleton root group. A user's
// `root_role` seeds one root-group role ASSIGNMENT: "owner" (the built-in apex,
// root:*, present by default on every group) is seeded SEED-IF-ABSENT via the
// genesis path; any other name must be a catalog role of the root persona
// (declared in core.Config, e.g. an app's bounded "admin").
type BootstrapManifest = authkit.BootstrapManifest

type BootstrapManifestUser = authkit.BootstrapManifestUser

type BootstrapManifestRemoteApplication = authkit.BootstrapManifestRemoteApplication

type BootstrapUserPassword = authkit.BootstrapUserPassword

type BootstrapReconcileOptions = authkit.BootstrapReconcileOptions

type BootstrapManifestResult = authkit.BootstrapManifestResult

func ParseBootstrapManifestYAML(raw []byte) (BootstrapManifest, error) {
	var manifest BootstrapManifest
	dec := yaml.NewDecoder(strings.NewReader(string(raw)))
	dec.KnownFields(true)
	if err := dec.Decode(&manifest); err != nil {
		return BootstrapManifest{}, err
	}
	if len(manifest.Users) == 0 && len(manifest.RemoteApplications) == 0 && len(manifest.Dev.StaticEntitlements) == 0 {
		return BootstrapManifest{}, ErrInvalidBootstrapManifest
	}
	// Parse is env-less and structural-only; the https/private jwks_uri policy
	// is enforced at apply time against the target service's environment (#257).
	if err := validateBootstrapManifest(manifest, true); err != nil {
		return BootstrapManifest{}, err
	}
	return manifest, nil
}

func LoadBootstrapManifestFile(path string) (BootstrapManifest, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		path = DefaultBootstrapManifestPath
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return BootstrapManifest{}, err
	}
	return ParseBootstrapManifestYAML(raw)
}

// ApplyBootstrapManifest commits seed data and its StartupOnly completion claim
// together. All manifests in one schema serialize, regardless of their names.
func (s *Client) ApplyBootstrapManifest(ctx context.Context, manifest BootstrapManifest, opts BootstrapReconcileOptions) (result BootstrapManifestResult, err error) {
	if err = s.requirePG(); err != nil {
		return result, err
	}
	if err = validateBootstrapManifest(manifest, s.cfg.Applications.AllowPrivateNetworkJWKS); err != nil {
		return result, err
	}
	schema := s.groupSchemaOrDefault()
	checkRole := func(raw string) error {
		role := normalizeRootRoleSlug(authkit.Role(raw))
		if role != "" && !s.validRoleForPersona(schema, RootPersona, role) {
			return fmt.Errorf("bootstrap root role %q: %w", role, authkit.ErrRoleNotAssignable)
		}
		return nil
	}
	for _, user := range manifest.Users {
		if _, _, _, _, _, _, _, err = normalizeImportUserInput(bootstrapImportUserInput(user)); err != nil {
			return result, err
		}
		if err = checkRole(user.RootRole); err != nil {
			return result, err
		}
	}
	for _, app := range manifest.RemoteApplications {
		if err = checkRole(app.RootRole); err != nil {
			return result, err
		}
	}
	result.DryRun = opts.DryRun
	if opts.DryRun {
		result.UsersCreated = len(manifest.Users)
		for _, user := range manifest.Users {
			result.PasswordsSet += boolToInt(user.Password != nil)
			result.RootRoleAssignments += boolToInt(strings.TrimSpace(user.RootRole) != "")
		}
		result.RemoteApplications = len(manifest.RemoteApplications)
		for _, app := range manifest.RemoteApplications {
			result.RemoteAppRootRoles += boolToInt(strings.TrimSpace(app.RootRole) != "")
		}
		return result, nil
	}
	// Do password hashing before holding database locks. Equality is checked
	// against the current stored credential under its account lock below.
	passwords := make([]db.UserPasswordUpsertParams, len(manifest.Users))
	for i, user := range manifest.Users {
		if user.Password != nil {
			if passwords[i], err = prepareBootstrapPassword(*user.Password); err != nil {
				return result, err
			}
		}
	}
	tx, err := s.beginAuthorityTransaction(ctx)
	if err != nil {
		return result, err
	}
	defer tx.Rollback(ctx)
	defer func() {
		if err != nil {
			result = BootstrapManifestResult{}
		}
	}()
	raw := tx
	if err = s.lockAuthority(ctx, raw); err != nil {
		return result, err
	}
	if _, err = raw.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1, 0))`, "authkit.bootstrap."+s.dbSchema()); err != nil {
		return result, err
	}
	if opts.StartupOnly {
		if result.AlreadyApplied, err = s.claimBootstrapApply(ctx, raw, opts.Name); err != nil {
			return result, err
		}
		if result.AlreadyApplied {
			return result, tx.Commit(ctx)
		}
	}
	q := s.qtx(tx)
	groups := s.groupStoreFor(raw)
	rootID, err := groups.ensureRootGroup(ctx)
	if err != nil {
		return result, err
	}
	if err = groups.SeedContainment(ctx, schema); err != nil {
		return result, err
	}
	for _, app := range manifest.RemoteApplications {
		if err = s.applyBootstrapRemoteApplication(ctx, groups, rootID, app); err != nil {
			return result, err
		}
		result.RemoteApplications++
		result.RemoteAppRootRoles += boolToInt(strings.TrimSpace(app.RootRole) != "")
	}
	owners, err := groups.OwnerCount(ctx, rootID)
	if err != nil {
		return result, err
	}
	type revokedSessions struct {
		userID string
		ids    []revokedSession
	}
	var revocations []revokedSessions
	for i, user := range manifest.Users {
		applied, created, applyErr := s.applyBootstrapUser(ctx, tx, user)
		if applyErr != nil {
			return result, applyErr
		}
		if created {
			result.UsersCreated++
		} else {
			result.UsersUpdated++
		}
		if user.Password != nil {
			if created || user.Password.Enforce {
				set, revoked, passwordErr := s.applyBootstrapUserPassword(ctx, q, applied.ID, *user.Password, passwords[i])
				if passwordErr != nil {
					return result, passwordErr
				}
				if set {
					result.PasswordsSet++
				} else {
					result.PasswordsKept++
				}
				if len(revoked) > 0 {
					revocations = append(revocations, revokedSessions{applied.ID, revoked})
				}
			} else {
				result.PasswordsKept++
			}
		}
		role := normalizeRootRoleSlug(authkit.Role(user.RootRole))
		if role == "" {
			continue
		}
		// Existing owners are never displaced by seed-if-absent owner entries.
		// Bootstrap is the one role seed that bypasses MFA enrollment.
		if role != OwnerRoleName || owners == 0 {
			if role != OwnerRoleName {
				if err = s.refuseOwnerLoss(ctx, groups, rootID, authkit.UserSubject(applied.ID)); err != nil {
					return result, err
				}
			}
			if err = groups.AssignRole(ctx, rootID, authkit.UserSubject(applied.ID), role); err != nil {
				return result, err
			}
		}
		result.RootRoleAssignments++
	}
	if err = tx.Commit(ctx); err != nil {
		return result, err
	}
	for _, revoke := range revocations {
		s.logRevokedSessions(ctx, revoke.userID, revoke.ids, string(SessionRevokeReasonAdminSetPassword))
	}
	s.logRBACDrift(ctx)
	return result, nil
}

func (s *Client) bootstrapApplyName(name string) string {
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
func (s *Client) claimBootstrapApply(ctx context.Context, q db.DBTX, name string) (already bool, err error) {
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
		return false, ErrBootstrapDatabaseNotEmpty
	}
	_, err = q.Exec(ctx, `INSERT INTO bootstrap_applies (name) VALUES ($1)`, name)
	return anyClaimed, err
}

func validateBootstrapManifest(manifest BootstrapManifest, allowInsecureJWKS bool) error {
	for _, user := range manifest.Users {
		username := strings.TrimSpace(user.Username)
		if username == "" {
			return ErrInvalidBootstrapManifest
		}
		if user.Password != nil {
			if err := validateBootstrapUserPassword(*user.Password); err != nil {
				return err
			}
		}
	}
	for _, app := range manifest.RemoteApplications {
		if strings.TrimSpace(app.Slug) == "" || strings.TrimSpace(app.Issuer) == "" || app.Enabled == nil {
			return ErrInvalidBootstrapManifest
		}
		if _, err := NormalizeRemoteAppTrustSource(app.JWKSURI, "", app.PublicKeys, TrustSourcePolicy{AllowPrivateNetworkJWKS: allowInsecureJWKS}); err != nil {
			return err
		}
	}
	return nil
}

func (s *Client) applyBootstrapRemoteApplication(ctx context.Context, groups *PermissionGroupStore, rootID string, app BootstrapManifestRemoteApplication) error {
	ra, err := s.upsertRemoteApplication(ctx, groups, RemoteApplication{
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
	role := normalizeRootRoleSlug(authkit.Role(app.RootRole))
	if role == "" {
		return nil
	}
	if role != OwnerRoleName {
		if err := s.refuseOwnerLoss(ctx, groups, rootID, authkit.RemoteAppSubject(ra.ID)); err != nil {
			return err
		}
	}
	return groups.AssignRole(ctx, rootID, authkit.RemoteAppSubject(ra.ID), role)
}

func validateBootstrapUserPassword(p BootstrapUserPassword) error {
	modes := 0
	if strings.TrimSpace(p.Plaintext) != "" {
		modes++
		if err := ValidatePassword(p.Plaintext); err != nil {
			return err
		}
	}
	if strings.TrimSpace(p.Hash) != "" || strings.TrimSpace(p.HashAlgo) != "" {
		modes++
		if strings.TrimSpace(p.Hash) == "" || strings.TrimSpace(p.HashAlgo) == "" {
			return ErrInvalidBootstrapManifest
		}
		if err := validatePasswordHashForStorage(strings.TrimSpace(p.Hash), strings.TrimSpace(p.HashAlgo)); err != nil {
			return fmt.Errorf("%w: %w", ErrInvalidBootstrapManifest, err)
		}
	}
	if p.ResetRequired {
		modes++
	}
	if modes != 1 {
		return ErrInvalidBootstrapManifest
	}
	// enforce-as-desired-state is incompatible with reset_required (#89): a
	// reset sentinel re-applied every reconcile would force a reset on every run.
	if p.Enforce && (p.ResetRequired || strings.TrimSpace(p.HashAlgo) == HashAlgoLegacyResetRequired) {
		return ErrInvalidBootstrapManifest
	}
	return nil
}

func (s *Client) applyBootstrapUser(ctx context.Context, tx pgx.Tx, user BootstrapManifestUser) (*User, bool, error) {
	q := s.qtx(tx)
	existing, err := s.findBootstrapUser(ctx, q, user)
	if err != nil {
		return nil, false, err
	}
	input := bootstrapImportUserInput(user)
	if existing == nil {
		applied, err := s.importUser(ctx, q, input)
		return applied, true, err
	}
	applied, err := s.updateImportedUserTx(ctx, tx, existing.ID, input)
	return applied, false, err
}

func (s *Client) findBootstrapUser(ctx context.Context, q *db.Queries, user BootstrapManifestUser) (*User, error) {
	if username := strings.TrimSpace(user.Username); username != "" {
		resolution, err := q.ResolveUsername(ctx, db.ResolveUsernameParams{Name: username, AtTime: s.namingNow()})
		if err == nil {
			row, err := q.UserByID(ctx, resolution.ID)
			if err != nil {
				return nil, err
			}
			return userFromByIDRow(row), nil
		}
		if err != nil && !errors.Is(err, pgx.ErrNoRows) {
			return nil, err
		}
	}
	if email := strings.TrimSpace(user.Email); email != "" {
		row, err := q.UserByEmail(ctx, NormalizeEmail(email))
		if err == nil {
			return userFromByEmailRow(row), nil
		}
		if err != nil && !errors.Is(err, pgx.ErrNoRows) {
			return nil, err
		}
	}
	if phone := strings.TrimSpace(user.PhoneNumber); phone != "" {
		normalized := NormalizePhone(phone)
		row, err := q.UserByPhone(ctx, &normalized)
		if err == nil {
			return userFromByPhoneRow(row), nil
		}
		if err != nil && !errors.Is(err, pgx.ErrNoRows) {
			return nil, err
		}
	}
	return nil, nil
}

func bootstrapImportUserInput(user BootstrapManifestUser) ImportUserInput {
	input := ImportUserInput{
		Email:         user.Email,
		PhoneNumber:   user.PhoneNumber,
		Username:      user.Username,
		EmailVerified: user.EmailVerified,
		PhoneVerified: user.PhoneVerified,
		BannedAt:      user.BannedAt,
		BannedUntil:   user.BannedUntil,
		BanReason:     user.BanReason,
		BannedBy:      user.BannedBy,
		Metadata:      user.Metadata,
	}
	if user.Banned && input.BannedAt == nil {
		now := time.Now().UTC()
		input.BannedAt = &now
	}
	return input
}

func prepareBootstrapPassword(p BootstrapUserPassword) (out db.UserPasswordUpsertParams, err error) {
	if plaintext := strings.TrimSpace(p.Plaintext); plaintext != "" {
		out.PasswordHash, err = password.HashArgon2id(plaintext)
		out.HashAlgo = "argon2id"
	} else if p.ResetRequired {
		out.PasswordHash, out.HashAlgo = "reset-required", HashAlgoLegacyResetRequired
	} else {
		out.PasswordHash, out.HashAlgo = strings.TrimSpace(p.Hash), strings.TrimSpace(p.HashAlgo)
	}
	return out, err
}

func (s *Client) applyBootstrapUserPassword(ctx context.Context, q *db.Queries, userID string, p BootstrapUserPassword, prepared db.UserPasswordUpsertParams) (bool, []revokedSession, error) {
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
