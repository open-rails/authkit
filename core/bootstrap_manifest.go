package core

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"gopkg.in/yaml.v3"
)

const DefaultBootstrapManifestPath = "/etc/authkit/bootstrap.yaml"

var ErrInvalidBootstrapManifest = errors.New("invalid_bootstrap_manifest")

// BootstrapManifest is AuthKit's first-class closed-deployment authority
// manifest. It owns AuthKit state only: users, global roles, orgs, org RBAC,
// trusted issuers, and generated API-key outputs.
type BootstrapManifest struct {
	Users       []BootstrapManifestUser       `json:"users" yaml:"users"`
	GlobalRoles []BootstrapManifestGlobalRole `json:"global_roles" yaml:"global_roles"`
	Orgs        []OrgManifestOrg              `json:"orgs" yaml:"orgs"`
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
	GlobalRoles   []string               `json:"global_roles" yaml:"global_roles"`
}

type BootstrapManifestGlobalRole struct {
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
	DryRun                bool              `json:"dry_run"`
	UsersCreated          int               `json:"users_created"`
	UsersUpdated          int               `json:"users_updated"`
	PasswordsSet          int               `json:"passwords_set"`
	PasswordsKept         int               `json:"passwords_kept"`
	GlobalRoles           int               `json:"global_roles"`
	GlobalRoleAssignments int               `json:"global_role_assignments"`
	OrgManifest           OrgManifestResult `json:"org_manifest"`
}

type BootstrapTokenStore = OrgManifestTokenStore
type BootstrapAPIKeyOutput = OrgManifestAPIKeyOutput
type FileBootstrapTokenStore = FileOrgManifestTokenStore

func ParseBootstrapManifestYAML(raw []byte) (BootstrapManifest, error) {
	var manifest BootstrapManifest
	dec := yaml.NewDecoder(strings.NewReader(string(raw)))
	dec.KnownFields(true)
	if err := dec.Decode(&manifest); err != nil {
		return BootstrapManifest{}, err
	}
	if len(manifest.Users) == 0 && len(manifest.GlobalRoles) == 0 && len(manifest.Orgs) == 0 {
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

func (s *Service) ReconcileBootstrapManifest(ctx context.Context, manifest BootstrapManifest, store BootstrapTokenStore, opts BootstrapReconcileOptions) (BootstrapManifestResult, error) {
	if err := s.requirePG(); err != nil {
		return BootstrapManifestResult{}, err
	}
	if err := validateBootstrapManifest(manifest); err != nil {
		return BootstrapManifestResult{}, err
	}

	result := BootstrapManifestResult{DryRun: opts.DryRun}
	userRefs := map[string]string{}
	if opts.DryRun {
		result.UsersCreated = len(manifest.Users)
		for _, role := range manifest.GlobalRoles {
			if strings.TrimSpace(role.Slug) != "" {
				result.GlobalRoles++
			}
		}
		for _, user := range manifest.Users {
			result.PasswordsSet += boolToInt(user.Password != nil)
			result.GlobalRoleAssignments += len(user.GlobalRoles)
			registerDryRunUserRefs(userRefs, user)
		}
		orgManifest, err := bootstrapOrgManifest(manifest, userRefs)
		if err != nil {
			return result, err
		}
		result.OrgManifest.Orgs = len(orgManifest.Orgs)
		for _, org := range orgManifest.Orgs {
			apiKeys, err := org.apiKeys()
			if err != nil {
				return result, err
			}
			result.OrgManifest.Issuers += len(org.Issuers)
			result.OrgManifest.Roles += len(org.Roles)
			result.OrgManifest.Memberships += len(org.Memberships)
			result.OrgManifest.APIKeysMinted += len(apiKeys)
		}
		return result, nil
	}

	for _, role := range manifest.GlobalRoles {
		slug := strings.ToLower(strings.TrimSpace(role.Slug))
		if slug == "" {
			continue
		}
		if err := s.UpsertRoleBySlug(ctx, role.Name, slug, role.Description); err != nil {
			return result, err
		}
		result.GlobalRoles++
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
		registerBootstrapUserRefs(userRefs, user, applied.ID)
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
		for _, role := range user.GlobalRoles {
			slug := strings.ToLower(strings.TrimSpace(role))
			if slug == "" {
				continue
			}
			if err := s.UpsertRoleBySlug(ctx, slug, slug, nil); err != nil {
				return result, err
			}
			if err := s.AssignRoleBySlug(ctx, applied.ID, slug); err != nil {
				return result, err
			}
			result.GlobalRoleAssignments++
		}
	}

	orgManifest, err := bootstrapOrgManifest(manifest, userRefs)
	if err != nil {
		return result, err
	}
	if len(orgManifest.Orgs) > 0 {
		orgResult, err := s.ReconcileOrgManifest(ctx, orgManifest, store)
		if err != nil {
			return result, err
		}
		result.OrgManifest = orgResult
	}
	return result, nil
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
	for _, role := range manifest.GlobalRoles {
		if strings.TrimSpace(role.Slug) == "" {
			return ErrInvalidBootstrapManifest
		}
	}
	for _, org := range manifest.Orgs {
		if strings.TrimSpace(org.Slug) == "" {
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

func bootstrapOrgManifest(manifest BootstrapManifest, userRefs map[string]string) (OrgManifest, error) {
	orgs := make([]OrgManifestOrg, len(manifest.Orgs))
	copy(orgs, manifest.Orgs)
	for i := range orgs {
		memberships := make([]OrgManifestMembership, len(orgs[i].Memberships))
		copy(memberships, orgs[i].Memberships)
		for j := range memberships {
			if strings.TrimSpace(memberships[j].UserID) == "" {
				ref := strings.TrimSpace(memberships[j].UserRef)
				if ref != "" {
					userID := strings.TrimSpace(userRefs[ref])
					if userID == "" {
						return OrgManifest{}, fmt.Errorf("%w: unknown user_ref %q", ErrInvalidBootstrapManifest, ref)
					}
					memberships[j].UserID = userID
				}
			}
			memberships[j].UserRef = ""
		}
		orgs[i].Memberships = memberships
	}
	return OrgManifest{Orgs: orgs}, nil
}

func (s *Service) resolveOrgManifestMembershipUserID(ctx context.Context, membership OrgManifestMembership) (string, error) {
	if userID := strings.TrimSpace(membership.UserID); userID != "" {
		return userID, nil
	}
	if strings.TrimSpace(membership.UserRef) != "" {
		return "", ErrInvalidOrgManifest
	}
	if username := strings.TrimSpace(membership.Username); username != "" {
		user, err := s.getUserByUsername(ctx, username)
		if errors.Is(err, pgx.ErrNoRows) || user == nil {
			return "", ErrInvalidOrgOwner
		}
		if err != nil {
			return "", err
		}
		return user.ID, nil
	}
	if email := strings.TrimSpace(membership.Email); email != "" {
		user, err := s.getUserByEmail(ctx, NormalizeEmail(email))
		if errors.Is(err, pgx.ErrNoRows) || user == nil {
			return "", ErrInvalidOrgOwner
		}
		if err != nil {
			return "", err
		}
		return user.ID, nil
	}
	return "", nil
}

func registerBootstrapUserRefs(refs map[string]string, user BootstrapManifestUser, userID string) {
	if ref := strings.TrimSpace(user.Ref); ref != "" {
		refs[ref] = userID
	}
	if username := strings.TrimSpace(user.Username); username != "" {
		refs["username:"+username] = userID
	}
	if email := strings.TrimSpace(user.Email); email != "" {
		refs["email:"+NormalizeEmail(email)] = userID
	}
}

func registerDryRunUserRefs(refs map[string]string, user BootstrapManifestUser) {
	if ref := strings.TrimSpace(user.Ref); ref != "" {
		refs[ref] = ref
	}
	if username := strings.TrimSpace(user.Username); username != "" {
		refs["username:"+username] = username
	}
	if email := strings.TrimSpace(user.Email); email != "" {
		refs["email:"+NormalizeEmail(email)] = email
	}
}

func boolToInt(v bool) int {
	if v {
		return 1
	}
	return 0
}
