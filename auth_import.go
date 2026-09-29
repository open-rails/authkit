package authkit

import (
	"context"
	"os"
	"strings"

	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/internal/engine"
)

// Bootstrap, the first admin, bulk import and provider links. These are host
// operations with no HTTP exposure: every one takes iam.OperatorActor() and
// refuses any other actor. None of them lets an account someone else
// registered gain authority through an unverified email or phone, a username
// or an alias.

// ApplyBootstrapManifest seeds accounts, their root roles and remote
// applications. See iam.BootstrapManifestUser for how existing accounts are
// found; nothing runs it implicitly.
func (a *Auth) ApplyBootstrapManifest(ctx context.Context, actor iam.Actor, m iam.BootstrapManifest, o iam.BootstrapOptions) (iam.BootstrapResult, error) {
	return a.engine.ApplyBootstrapManifest(ctx, actor, m, o)
}

// EnsureUserRole makes the account u names hold role in ref, and is safe to
// call on every boot. With no account for the email or phone, it creates one
// without credentials and with the contact unverified: only a proof of that
// contact (a password reset or a passwordless sign-in) can ever sign in to it,
// and that proof verifies it. An existing account is used when u is its id,
// when the contact is verified, or when it already holds role, the group's
// owner role, or a role covering role (a re-run, including on the account an
// earlier call created). Any other account gets iam.ErrContactNotVerified,
// so a pre-registered account is never adopted. A username never finds one.
func (a *Auth) EnsureUserRole(ctx context.Context, actor iam.Actor, ref iam.GroupRef, u iam.UserRef, role iam.Role) (iam.User, error) {
	return a.engine.EnsureUserRole(ctx, actor, ref, u, role)
}

// ImportUsers imports accounts in bulk (hundreds of thousands per call), in
// chunks that commit independently. Every row is reported: see iam.ImportRow
// and iam.ImportConflict. Invalid rows are rejected alone; a database error
// stops the import and the rows of committed chunks are still reported.
func (a *Auth) ImportUsers(ctx context.Context, actor iam.Actor, rows []iam.ImportUser, o iam.ImportOptions) (iam.ImportResult, error) {
	return a.engine.ImportUsers(ctx, actor, rows, o)
}

// ImportSolanaLinks reserves legacy wallet addresses for their accounts
// without making them login methods; only a later Sign-In with Solana proof
// verifies one.
func (a *Auth) ImportSolanaLinks(ctx context.Context, actor iam.Actor, rows []iam.ImportSolanaLink) (iam.ImportSolanaLinksResult, error) {
	return a.engine.ImportSolanaLinks(ctx, actor, rows)
}

// LinkProvider links an external identity to an account as a login method.
// Browser flows link through the provider login instead.
func (a *Auth) LinkProvider(ctx context.Context, actor iam.Actor, userID string, l iam.ProviderLink) error {
	return a.engine.LinkProvider(ctx, actor, userID, l)
}

// DefaultBootstrapManifestPath is where LoadBootstrapManifestFile reads when
// given no path.
const DefaultBootstrapManifestPath = "/etc/authkit/bootstrap.yaml"

// ParseBootstrapManifestYAML parses a bootstrap manifest, rejecting unknown
// fields, empty manifests and structurally invalid entries.
func ParseBootstrapManifestYAML(raw []byte) (iam.BootstrapManifest, error) {
	return engine.ParseBootstrapManifestYAML(raw)
}

// LoadBootstrapManifestFile reads and parses a bootstrap manifest; an empty
// path reads DefaultBootstrapManifestPath.
func LoadBootstrapManifestFile(path string) (iam.BootstrapManifest, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		path = DefaultBootstrapManifestPath
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return iam.BootstrapManifest{}, err
	}
	return ParseBootstrapManifestYAML(raw)
}
