package authcore

import (
	"context"
	"encoding/json"
	"errors"
	authkit "github.com/open-rails/authkit"
	"os"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/open-rails/authkit/internal/db"
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
	if len(manifest.Users) == 0 && len(manifest.RemoteApplications) == 0 {
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

func (s *Service) ApplyBootstrapManifest(ctx context.Context, manifest BootstrapManifest, opts BootstrapReconcileOptions) (BootstrapManifestResult, error) {
	if err := s.requirePG(); err != nil {
		return BootstrapManifestResult{}, err
	}
	if err := validateBootstrapManifest(manifest, s.isDevEnvironment()); err != nil {
		return BootstrapManifestResult{}, err
	}

	result := BootstrapManifestResult{DryRun: opts.DryRun}
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
	claimed := false
	if opts.StartupOnly {
		unlock, err := s.lockBootstrapApply(ctx, opts.Name)
		if err != nil {
			return result, err
		}
		defer unlock()

		var already bool
		claimed, already, err = s.claimBootstrapApply(ctx, opts.Name)
		if err != nil {
			return result, err
		}
		if already {
			result.AlreadyApplied = true
			return result, nil
		}
		defer func() {
			if claimed {
				_ = s.releaseBootstrapApply(ctx, opts.Name)
			}
		}()
	}

	// The root permission-group is the operator authority plane (#111). Ensure it
	// exists and seed the declared containment so any root-role assignment lands.
	if _, err := s.EnsureRootGroup(ctx); err != nil {
		return result, err
	}
	if err := s.SeedPermissionGroupContainment(ctx); err != nil {
		return result, err
	}

	for _, app := range manifest.RemoteApplications {
		if err := s.applyBootstrapRemoteApplication(ctx, app); err != nil {
			return result, err
		}
		result.RemoteApplications++
		result.RemoteAppRootRoles += boolToInt(strings.TrimSpace(app.RootRole) != "")
	}

	// #136: owner is the apex and is seeded SEED-IF-ABSENT (break-glass) — compute
	// owner presence ONCE so a manifest never re-asserts owners once any exist
	// (runtime owner management wins; the manifest only fires from a zero-owner
	// state to recover from lockout).
	rootHasOwner, err := s.rootGroupHasOwner(ctx)
	if err != nil {
		return result, err
	}

	for _, user := range manifest.Users {
		applied, created, err := s.applyBootstrapUser(ctx, user)
		if err != nil {
			return result, err
		}
		if created {
			result.UsersCreated++
		} else {
			result.UsersUpdated++
		}
		if user.Password != nil {
			// Seed-once (#89): apply a manifest password only when the user was
			// just CREATED, or when the password explicitly opts into
			// enforce-as-desired-state. Otherwise a password rotated out of band
			// after the initial seed would be reverted on every reconcile.
			if created || user.Password.Enforce {
				set, err := s.applyBootstrapUserPassword(ctx, applied.ID, *user.Password)
				if err != nil {
					return result, err
				}
				if set {
					result.PasswordsSet++
				} else {
					result.PasswordsKept++
				}
			} else {
				result.PasswordsKept++
			}
		}
		slug := strings.ToLower(strings.TrimSpace(user.RootRole))
		if slug == "" {
			continue
		}
		// #136: seed the genesis user's root role. "owner" (the apex, root:*)
		// is seed-if-absent and uses the genesis path that bypasses the runtime
		// owner-reserved guard; any other declared root role assigns directly.
		if err := s.seedBootstrapRootRole(ctx, applied.ID, slug, rootHasOwner); err != nil {
			return result, err
		}
		result.RootRoleAssignments++
	}

	claimed = false
	return result, nil
}

func (s *Service) bootstrapApplyName(name string) string {
	if name = strings.TrimSpace(name); name != "" {
		return name
	}
	return defaultBootstrapApplyName
}

func (s *Service) lockBootstrapApply(ctx context.Context, name string) (func(), error) {
	name = "authkit.bootstrap." + s.bootstrapApplyName(name)
	conn, err := s.pg.Acquire(ctx)
	if err != nil {
		return nil, err
	}
	if _, err := conn.Exec(ctx, `SELECT pg_advisory_lock(hashtextextended($1, 0))`, name); err != nil {
		conn.Release()
		return nil, err
	}
	return func() {
		_, _ = conn.Exec(context.Background(), `SELECT pg_advisory_unlock(hashtextextended($1, 0))`, name)
		conn.Release()
	}, nil
}

func (s *Service) claimBootstrapApply(ctx context.Context, name string) (claimed, already bool, err error) {
	q := db.ForSchema(s.pg, s.dbSchema())
	name = s.bootstrapApplyName(name)
	var exists bool
	if err := q.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM profiles.bootstrap_applies WHERE name = $1)`, name).Scan(&exists); err != nil {
		return false, false, err
	}
	if exists {
		return false, true, nil
	}
	var stateRows int64
	if err := q.QueryRow(ctx, `
		SELECT
			(SELECT count(*) FROM profiles.users WHERE deleted_at IS NULL)
			+
			(SELECT count(*) FROM profiles.remote_applications)
	`).Scan(&stateRows); err != nil {
		return false, false, err
	}
	if stateRows > 0 {
		return false, false, ErrBootstrapDatabaseNotEmpty
	}
	tag, err := q.Exec(ctx, `INSERT INTO profiles.bootstrap_applies (name) VALUES ($1) ON CONFLICT DO NOTHING`, name)
	if err != nil {
		return false, false, err
	}
	if tag.RowsAffected() == 0 {
		return false, true, nil
	}
	return true, false, nil
}

func (s *Service) releaseBootstrapApply(ctx context.Context, name string) error {
	_, err := db.ForSchema(s.pg, s.dbSchema()).Exec(ctx, `DELETE FROM profiles.bootstrap_applies WHERE name = $1`, s.bootstrapApplyName(name))
	return err
}

// rootGroupHasOwner reports whether the singleton root group currently has any
// owner. Used to make manifest owner-seeding seed-if-absent (#136).
func (s *Service) rootGroupHasOwner(ctx context.Context) (bool, error) {
	members, err := s.ListGroupMembers(ctx, RootPersona, "")
	if err != nil {
		if errors.Is(err, ErrGroupNotFound) {
			return false, nil
		}
		return false, err
	}
	for _, m := range members {
		if m.Role == OwnerRoleName {
			return true, nil
		}
	}
	return false, nil
}

// seedBootstrapRootRole seeds one root role for a genesis (manifest) user.
// "owner" — the apex (root:*) — is SEED-IF-ABSENT and goes through the genesis
// path (AssignGroupRoleGenesis) that bypasses both the runtime owner-reserved
// guard (#136) and the MFA-required-role gate (#148/root-owner-MFA) — a
// manifest-seeded user has no session to have enrolled MFA with, so bootstrap
// must never brick on it; any other declared root role is assigned the same
// way via assignRoleBySlugGenesis. The manifest is the deploy-time trust root
// and the ONE seam that bypasses these runtime rules — GenesisClient does NOT
// bypass the MFA gate.
func (s *Service) seedBootstrapRootRole(ctx context.Context, userID, slug string, rootHasOwner bool) error {
	if strings.EqualFold(slug, OwnerRoleName) {
		if rootHasOwner {
			return nil // break-glass: owners already exist; don't fight runtime
		}
		return s.AssignGroupRoleGenesis(ctx, RootPersona, "", userID, SubjectKindUser, OwnerRoleName)
	}
	return s.assignRoleBySlugGenesis(ctx, userID, slug)
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
		if _, err := NormalizeRemoteAppTrustSource(app.JWKSURI, "", app.PublicKeys, allowInsecureJWKS); err != nil {
			return err
		}
	}
	return nil
}

func (s *Service) applyBootstrapRemoteApplication(ctx context.Context, app BootstrapManifestRemoteApplication) error {
	gid, err := s.ResolveGroupIDForSlug(ctx, RootPersona, "")
	if err != nil {
		return err
	}
	ra, err := s.UpsertRemoteApplication(ctx, RemoteApplication{
		Slug:              strings.TrimSpace(app.Slug),
		PermissionGroupID: gid,
		Issuer:            strings.TrimSpace(app.Issuer),
		JWKSURI:           strings.TrimSpace(app.JWKSURI),
		PublicKeys:        app.PublicKeys,
		Enabled:           *app.Enabled,
	})
	if err != nil {
		return err
	}
	role := strings.TrimSpace(app.RootRole)
	if role == "" {
		return nil
	}
	return s.AddRemoteApplicationMember(ctx, ra.ID, role)
}

func validateBootstrapUserPassword(p BootstrapUserPassword) error {
	modes := 0
	if strings.TrimSpace(p.Plaintext) != "" {
		modes++
		if err := ValidatePassword(p.Plaintext); err != nil {
			return err
		}
	}
	if strings.TrimSpace(p.Hash) != "" || strings.TrimSpace(p.HashAlgo) != "" || len(p.HashParams) > 0 {
		modes++
		if strings.TrimSpace(p.Hash) == "" || strings.TrimSpace(p.HashAlgo) == "" {
			return ErrInvalidBootstrapManifest
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
	if p.Enforce && p.ResetRequired {
		return ErrInvalidBootstrapManifest
	}
	return nil
}

func (s *Service) applyBootstrapUser(ctx context.Context, user BootstrapManifestUser) (*User, bool, error) {
	existing, err := s.findBootstrapUser(ctx, user)
	if err != nil {
		return nil, false, err
	}
	input := bootstrapImportUserInput(user)
	if existing == nil {
		applied, err := s.ImportUser(ctx, input)
		return applied, true, err
	}
	applied, err := s.UpdateImportedUser(ctx, existing.ID, input)
	return applied, false, err
}

func (s *Service) findBootstrapUser(ctx context.Context, user BootstrapManifestUser) (*User, error) {
	if username := strings.TrimSpace(user.Username); username != "" {
		existing, err := s.getUserByUsername(ctx, username)
		if err == nil && existing != nil {
			return existing, nil
		}
		if err != nil && !errors.Is(err, pgx.ErrNoRows) {
			return nil, err
		}
	}
	if email := strings.TrimSpace(user.Email); email != "" {
		existing, err := s.getUserByEmail(ctx, NormalizeEmail(email))
		if err == nil && existing != nil {
			return existing, nil
		}
		if err != nil && !errors.Is(err, pgx.ErrNoRows) {
			return nil, err
		}
	}
	if phone := strings.TrimSpace(user.PhoneNumber); phone != "" {
		existing, err := s.GetUserByPhone(ctx, NormalizePhone(phone))
		if err == nil && existing != nil {
			return existing, nil
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

func (s *Service) applyBootstrapUserPassword(ctx context.Context, userID string, p BootstrapUserPassword) (bool, error) {
	if plaintext := strings.TrimSpace(p.Plaintext); plaintext != "" {
		if err := s.CheckUserPassword(ctx, userID, plaintext); err == nil {
			return false, nil
		}
		return true, s.AdminSetPassword(ctx, userID, plaintext)
	}
	if p.ResetRequired {
		return true, s.UpsertPasswordHash(ctx, userID, "reset-required", HashAlgoLegacyResetRequired, nil)
	}
	params, err := json.Marshal(p.HashParams)
	if err != nil {
		return false, err
	}
	return true, s.UpsertPasswordHash(ctx, userID, strings.TrimSpace(p.Hash), strings.TrimSpace(p.HashAlgo), params)
}

func boolToInt(v bool) int {
	if v {
		return 1
	}
	return 0
}
