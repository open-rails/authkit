package authkit

import (
	"context"

	"github.com/open-rails/authkit/iam"
)

// Bootstrap, the first admin, bulk import and provider links. These are host
// operations: your code decides, so they take no actor, and nothing on
// AuthKit's HTTP surface reaches them. The invariants still hold, and none of
// them lets an account someone else registered gain authority through an
// unverified email or phone, a username or an alias.

// ApplyBootstrapManifest seeds accounts, their root roles and remote
// applications. See iam.BootstrapManifestUser for how existing accounts are
// found; nothing runs it implicitly.
func (a *Client) ApplyBootstrapManifest(ctx context.Context, m iam.BootstrapManifest, o iam.BootstrapOptions, opts ...Option) (iam.BootstrapResult, error) {
	return a.ops.ApplyBootstrapManifest(ctx, m, o, opts...)
}

// EnsureUserRole makes the account u names hold role in group, and is safe
// to call on every boot. With no account for the email or phone, it creates one
// without credentials and with the contact unverified: only a proof of that
// contact (a password reset or a passwordless sign-in) can ever sign in to it,
// and that proof verifies it. An existing account is used when u is its id,
// when the contact is verified, or when it already holds role, the group's
// owner role, or a role covering role (a re-run, including on the account an
// earlier call created). Any other account gets iam.ErrContactNotVerified,
// so a pre-registered account is never adopted. A username never finds one.
func (a *Client) EnsureUserRole(ctx context.Context, group iam.GroupRef, u iam.UserRef, role iam.Role, opts ...Option) (iam.User, error) {
	return a.ops.EnsureUserRole(ctx, group, u, role, opts...)
}

// ImportUsers imports accounts in bulk (hundreds of thousands per call), in
// chunks that commit independently. Every row is reported: see iam.ImportRow
// and iam.ImportConflict. Invalid rows are rejected alone; a database error
// stops the import and the rows of committed chunks are still reported.
func (a *Client) ImportUsers(ctx context.Context, rows []iam.ImportUser, o iam.ImportOptions, opts ...Option) (iam.ImportResult, error) {
	return a.ops.ImportUsers(ctx, rows, o, opts...)
}

// ImportSolanaLinks reserves legacy wallet addresses for their accounts
// without making them login methods; only a later Sign-In with Solana proof
// verifies one.
func (a *Client) ImportSolanaLinks(ctx context.Context, rows []iam.ImportSolanaLink, opts ...Option) (iam.ImportSolanaLinksResult, error) {
	return a.ops.ImportSolanaLinks(ctx, rows, opts...)
}

// LinkProvider links an external identity to an account as a login method.
// Browser flows link through the provider login instead.
func (a *Client) LinkProvider(ctx context.Context, userID string, l iam.ProviderLink, opts ...Option) error {
	return a.ops.LinkProvider(ctx, userID, l, opts...)
}

// ParseBootstrapManifestYAML parses a bootstrap manifest, rejecting empty
// manifests, structurally invalid entries and a root_role that is not a root
// role of Config.Roles. An unknown key is logged as a warning, with its path
// (users[0].nickname), and ignored.
func (a *Client) ParseBootstrapManifestYAML(raw []byte) (iam.BootstrapManifest, error) {
	return a.ops.ParseBootstrapManifestYAML(raw)
}
