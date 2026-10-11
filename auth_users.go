package authkit

import (
	"context"

	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/helpers/auth"
)

// Accounts. Reads take no identity: the host is the trust boundary. Host
// operations (CreateUser, PurgeUsers, ResetAccountMFA) take none either: your
// code decides. Every other mutation takes the identity right after ctx;
// iam.SystemIdentity() is trusted host authority, and any other identity needs rule
// ACCT: the named root:users:* permission, outranking the target account on
// root (a peer or superior is iam.ErrAccountAuthorityEscalation: demote it
// first) and covering its grants in every group it holds a role in.

// User returns one account by iam.UserByID, UserByEmail, UserByPhone or
// UserByUsername. Soft-deleted accounts need IncludeDeleted(). A miss is
// iam.ErrUserNotFound. An address match proves nothing about who owns the
// account unless EmailVerified or PhoneVerified is set: never grant authority
// to an account found by an unverified address.
func (a *Client) User(ctx context.Context, ref iam.UserRef, opts ...Option) (iam.User, error) {
	return a.ops.User(ctx, ref, opts...)
}

// Users returns the accounts among any number of ids, deleted ones included;
// unknown ids are absent. It carries contact details: render other
// people with PublicUsers.
func (a *Client) Users(ctx context.Context, ids []string) (map[string]iam.User, error) {
	return a.ops.Users(ctx, ids)
}

// PublicUsers returns what other people may see of any number of ids: deleted
// accounts are tombstones, unknown ids are absent.
func (a *Client) PublicUsers(ctx context.Context, ids []string) (map[string]iam.PublicUser, error) {
	return a.ops.PublicUsers(ctx, ids)
}

// ListUsers pages through the user directory. Each entry carries the
// account's root role and, with q.WithEntitlements, its entitlements; q.Total
// counts every match.
func (a *Client) ListUsers(ctx context.Context, q iam.UserQuery) (iam.ListPage[iam.UserEntry], error) {
	return a.ops.ListUsers(ctx, q)
}

// ResolveUsername resolves a username, current or a live alias of a renamed
// account, to its account. An expired alias, a deleted account and a name
// kept for a purged account are iam.ErrUserNotFound.
func (a *Client) ResolveUsername(ctx context.Context, name string) (iam.NameResolution, error) {
	return a.ops.ResolveUsername(ctx, name)
}

// CheckUsername reports whether a new account could take name: nil, the
// username policy's validation error, iam.ErrUsernameInUse, or the
// NameAdmission refusal. A name is in use while any account holds it, as its
// name or a live alias, including its own; the answer says nothing more
// about that account. Serve it to untrusted callers only rate-limited.
func (a *Client) CheckUsername(ctx context.Context, name string) error {
	return a.ops.CheckUsername(ctx, name)
}

// DeviceKeys returns the account's device keys in enrollment order, revoked
// ones included. iam.ErrDeviceKeysDisabled without Config.DeviceKeys.Enabled.
func (a *Client) DeviceKeys(ctx context.Context, userID string) ([]iam.DeviceKey, error) {
	return a.ops.DeviceKeys(ctx, userID)
}

// CreateUser creates a native account. Host operation: your code decides.
func (a *Client) CreateUser(ctx context.Context, u iam.NewUser, opts ...Option) (iam.User, error) {
	return a.ops.CreateUser(ctx, u, opts...)
}

// UpdateUser changes an account under ACCT(root:users:manage). An account may
// change its own Username and PreferredLanguage. Password,
// PasswordHash and the verified flags are system-only. A verified flag
// asserts a proof, so never set one on another system's word: on an account
// with no proven contact it first retires the pre-proof credentials and the
// addresses the flags don't cover. An email change never moves the account's
// email factor.
func (a *Client) UpdateUser(ctx context.Context, who auth.Identity, userID string, u iam.UserUpdate, opts ...Option) (iam.User, error) {
	return a.ops.UpdateUser(ctx, who, userID, u, opts...)
}

// PatchPublicMetadata applies patch to the account's public metadata
// (iam.PublicUser.PublicMetadata) as an RFC 7396 JSON Merge Patch under
// ACCT(root:users:manage), never on the identity's own account: objects merge
// recursively, a nil value deletes its key, and any other value (arrays
// included) replaces the one it names. {"links": {"site": "https://…",
// "old": nil}} sets links.site, deletes links.old and keeps links' other
// keys. Only the host writes public metadata, and anyone may read it: GET
// /me, GET /users and PublicUsers return it whole. Keep private data in your
// own tables, keyed by the account id.
func (a *Client) PatchPublicMetadata(ctx context.Context, who auth.Identity, userID string, patch map[string]any, opts ...Option) error {
	return a.ops.PatchPublicMetadata(ctx, who, userID, patch, opts...)
}

// Ban bans an account under ACCT(root:users:ban) and revokes its sessions,
// device keys, and the API keys and invitations it issued. Nobody bans
// themselves.
func (a *Client) Ban(ctx context.Context, who auth.Identity, userID string, b iam.Ban, opts ...Option) error {
	return a.ops.Ban(ctx, who, userID, b, opts...)
}

// Unban lifts a ban under ACCT(root:users:ban). Nobody lifts their own ban.
func (a *Client) Unban(ctx context.Context, who auth.Identity, userID string, opts ...Option) error {
	return a.ops.Unban(ctx, who, userID, opts...)
}

// DeleteUsers soft-deletes accounts under ACCT(root:users:delete), starting
// the 30-day recovery window; an account may delete itself. Only a
// self-deletion is undone by signing in; any other comes back through
// RestoreUsers. Results are per item; the error is a whole-call failure.
func (a *Client) DeleteUsers(ctx context.Context, who auth.Identity, ids []string, opts ...Option) ([]iam.OpResult, error) {
	return a.ops.DeleteUsers(ctx, who, ids, opts...)
}

// RestoreUsers restores soft-deleted accounts within their recovery window
// under ACCT(root:users:delete).
func (a *Client) RestoreUsers(ctx context.Context, who auth.Identity, ids []string, opts ...Option) ([]iam.OpResult, error) {
	return a.ops.RestoreUsers(ctx, who, ids, opts...)
}

// PurgeUsers ends the recovery window of accounts now; the rows go once the
// host deletion callbacks complete. Host operation: your code decides.
//
// <schema>.users(id) is the one AuthKit column a host table may reference: a
// foreign key ON DELETE CASCADE (or SET NULL) keeps host rows for as long as
// the account row exists, through the recovery window, and removes them with
// it at purge. Every other AuthKit table is private.
func (a *Client) PurgeUsers(ctx context.Context, ids []string, opts ...Option) ([]iam.OpResult, error) {
	return a.ops.PurgeUsers(ctx, ids, opts...)
}

// ResetAccountMFA recovers an account that lost its second factors, such as a
// passkey-only account answering passkey_required. It deletes the account's
// passkeys, 2FA factors and backup codes, revokes its device keys and
// sessions, and notifies its address through the email sender. Roles stay:
// when one needs MFA, or 2FA is Required, the next sign-in enrolls a factor.
// Host operation: your code decides, so verify who is asking before calling
// it.
func (a *Client) ResetAccountMFA(ctx context.Context, userID string, opts ...Option) error {
	return a.ops.ResetAccountMFA(ctx, userID, opts...)
}

// UserAgreements returns every version of a Config.Agreements document the
// user accepted, with when and where (registration, their account, or the
// host). Gate a feature on a document's current version: OpenRails' network
// API on its network terms, say.
func (a *Client) UserAgreements(ctx context.Context, userID string) ([]iam.AgreementAcceptance, error) {
	return a.ops.UserAgreements(ctx, userID)
}

// AgreementsDue returns the documents the user is asked to accept now: one
// Registration.Agreements names that the account never accepted, and one
// marked Reaccept whose earlier version it accepted.
func (a *Client) AgreementsDue(ctx context.Context, userID string) ([]iam.Agreement, error) {
	return a.ops.AgreementsDue(ctx, userID)
}

// AcceptAgreements records the user's acceptance of documents at their
// current versions, given in the host's own flow (a merchant sign-up's
// terms, say); an earlier version is iam.ErrAgreementRequired.
func (a *Client) AcceptAgreements(ctx context.Context, userID string, agreements []iam.AgreementRef, opts ...Option) error {
	return a.ops.AcceptAgreements(ctx, userID, agreements, opts...)
}
