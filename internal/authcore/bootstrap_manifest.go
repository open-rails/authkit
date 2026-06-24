package authcore

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"gopkg.in/yaml.v3"
)

const DefaultBootstrapManifestPath = "/etc/authkit/bootstrap.yaml"

var ErrInvalidBootstrapManifest = errors.New("invalid_bootstrap_manifest")

// BootstrapManifest is AuthKit's first-class closed-deployment authority
// manifest. It owns AuthKit state only: users, root permission-group roles, and
// password seeding.
//
// Operator authority is a role assignment in the singleton root group. A user's
// `root_roles` seed root-group role ASSIGNMENTS: "owner" (the built-in apex,
// root:*, present by default on every group) is seeded SEED-IF-ABSENT via the
// genesis path; any other name must be a catalog role of the root persona
// (declared in core.Config — e.g. an app's bounded "admin"). The top-level
// `root_roles` role-DEFINITION list is vestigial under the permission-group model
// (catalog roles live in core.Config, not the manifest) and is accepted-but-ignored.
type BootstrapManifest struct {
	Users       []BootstrapManifestUser       `json:"users" yaml:"users"`
	RootRoles []BootstrapManifestRootRole `json:"root_roles" yaml:"root_roles"`
}

type BootstrapManifestUser struct {
	Ref           string                 `json:"ref" yaml:"ref"`
	Email         string                 `json:"email" yaml:"email"`
	PhoneNumber   string                 `json:"phone_number" yaml:"phone_number"`
	Username      string                 `json:"username" yaml:"username"`
	EmailVerified bool                   `json:"email_verified" yaml:"email_verified"`
	PhoneVerified bool                   `json:"phone_verified" yaml:"phone_verified"`
	Banned        bool                   `json:"banned" yaml:"banned"`
	BannedAt      *time.Time             `json:"banned_at" yaml:"banned_at"`
	BannedUntil   *time.Time             `json:"banned_until" yaml:"banned_until"`
	BanReason     *string                `json:"ban_reason" yaml:"ban_reason"`
	BannedBy      *string                `json:"banned_by" yaml:"banned_by"`
	Metadata      map[string]any         `json:"metadata" yaml:"metadata"`
	Password      *BootstrapUserPassword `json:"password" yaml:"password"`
	// RootRoles assigns root permission-group roles to this user by name. "owner"
	// (the built-in apex, root:*) is seeded SEED-IF-ABSENT; any other name is
	// assigned as a same-named catalog role of the root persona (e.g. an app's
	// bounded "admin").
	RootRoles []string `json:"root_roles" yaml:"root_roles"`
}

// BootstrapManifestRootRole is the vestigial top-level role-DEFINITION entry.
// Under the permission-group model catalog roles live in core.Config, not the
// manifest, so this is accepted-but-ignored; kept for manifest backward-compat.
type BootstrapManifestRootRole struct {
	Name        string  `json:"name" yaml:"name"`
	Slug        string  `json:"slug" yaml:"slug"`
	Description *string `json:"description" yaml:"description"`
}

type BootstrapUserPassword struct {
	Plaintext     string         `json:"plaintext" yaml:"plaintext"`
	Hash          string         `json:"hash" yaml:"hash"`
	HashAlgo      string         `json:"hash_algo" yaml:"hash_algo"`
	HashParams    map[string]any `json:"hash_params" yaml:"hash_params"`
	ResetRequired bool           `json:"reset_required" yaml:"reset_required"`
	// Enforce makes the password DESIRED-STATE (#89): re-asserted on every
	// reconcile. Default false = SEED-ONCE — the password is applied only when
	// the user is first created, so a password rotated out of band (via the
	// admin API) is never reverted to the manifest value on a later reconcile.
	// Must not be combined with ResetRequired (forcing a reset every run is
	// nonsensical).
	Enforce bool `json:"enforce" yaml:"enforce"`
}

type BootstrapReconcileOptions struct {
	DryRun bool
}

type BootstrapManifestResult struct {
	DryRun                bool `json:"dry_run"`
	UsersCreated          int  `json:"users_created"`
	UsersUpdated          int  `json:"users_updated"`
	PasswordsSet          int  `json:"passwords_set"`
	PasswordsKept         int  `json:"passwords_kept"`
	RootRoles           int  `json:"root_roles"`
	RootRoleAssignments int  `json:"root_role_assignments"`
}

func ParseBootstrapManifestYAML(raw []byte) (BootstrapManifest, error) {
	var manifest BootstrapManifest
	dec := yaml.NewDecoder(strings.NewReader(string(raw)))
	dec.KnownFields(true)
	if err := dec.Decode(&manifest); err != nil {
		return BootstrapManifest{}, err
	}
	if len(manifest.Users) == 0 && len(manifest.RootRoles) == 0 {
		return BootstrapManifest{}, ErrInvalidBootstrapManifest
	}
	if err := validateBootstrapManifest(manifest); err != nil {
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

func (s *Service) ReconcileBootstrapManifest(ctx context.Context, manifest BootstrapManifest, opts BootstrapReconcileOptions) (BootstrapManifestResult, error) {
	if err := s.requirePG(); err != nil {
		return BootstrapManifestResult{}, err
	}
	if err := validateBootstrapManifest(manifest); err != nil {
		return BootstrapManifestResult{}, err
	}

	result := BootstrapManifestResult{DryRun: opts.DryRun}
	if opts.DryRun {
		result.UsersCreated = len(manifest.Users)
		for _, role := range manifest.RootRoles {
			if strings.TrimSpace(role.Slug) != "" {
				result.RootRoles++
			}
		}
		for _, user := range manifest.Users {
			result.PasswordsSet += boolToInt(user.Password != nil)
			result.RootRoleAssignments += len(user.RootRoles)
		}
		return result, nil
	}

	// The root permission-group is the operator authority plane (#111). Ensure it
	// exists and seed the declared containment so any root-role assignment lands.
	if _, err := s.EnsureRootGroup(ctx); err != nil {
		return result, err
	}
	if err := s.SeedPermissionGroupContainment(ctx); err != nil {
		return result, err
	}

	for _, role := range manifest.RootRoles {
		slug := strings.ToLower(strings.TrimSpace(role.Slug))
		if slug == "" {
			continue
		}
		if err := s.UpsertRoleBySlug(ctx, role.Name, slug, role.Description); err != nil {
			return result, err
		}
		result.RootRoles++
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
		for _, role := range user.RootRoles {
			slug := strings.ToLower(strings.TrimSpace(role))
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
	}

	return result, nil
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
// path (AssignGroupRole) that bypasses the runtime owner-reserved guard; any
// other declared root role is assigned directly. Genesis seeding is the
// deploy-time trust root and intentionally bypasses the #136 runtime
// capability/no-escalation rules.
func (s *Service) seedBootstrapRootRole(ctx context.Context, userID, slug string, rootHasOwner bool) error {
	if strings.EqualFold(slug, OwnerRoleName) {
		if rootHasOwner {
			return nil // break-glass: owners already exist; don't fight runtime
		}
		return s.AssignGroupRole(ctx, RootPersona, "", userID, SubjectKindUser, OwnerRoleName)
	}
	return s.AssignRoleBySlug(ctx, userID, slug)
}

func validateBootstrapManifest(manifest BootstrapManifest) error {
	seenRefs := map[string]struct{}{}
	for _, user := range manifest.Users {
		username := strings.TrimSpace(user.Username)
		if username == "" {
			return ErrInvalidBootstrapManifest
		}
		if ref := strings.TrimSpace(user.Ref); ref != "" {
			if _, ok := seenRefs[ref]; ok {
				return ErrInvalidBootstrapManifest
			}
			seenRefs[ref] = struct{}{}
		}
		if user.Password != nil {
			if err := validateBootstrapUserPassword(*user.Password); err != nil {
				return err
			}
		}
	}
	for _, role := range manifest.RootRoles {
		if strings.TrimSpace(role.Slug) == "" {
			return ErrInvalidBootstrapManifest
		}
	}
	return nil
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
