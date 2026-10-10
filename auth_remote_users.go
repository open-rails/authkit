package authkit

import (
	"context"

	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/helpers/auth"
)

// Federated grants: a group's email invitation (CreateInvitation with Email
// and Role) may be accepted by a user of an issuer the group trusts, with a
// token (Authenticator, Config.Resource) whose verified email is the
// invitation's. That user then holds the role in the group: their tokens
// hold its permissions there, within their application's role.

// RemoteInvitations are the invitations v, a trusted issuer's user token
// with a verified email, may accept in its group; none for any other
// credential.
func (a *Client) RemoteInvitations(ctx context.Context, v auth.Verified) ([]iam.Invitation, error) {
	return a.engine.RemoteInvitations(ctx, v)
}

// AcceptRemoteInvitation redeems one of v's RemoteInvitations and answers
// the role v's user now holds in the group; iam.ErrInvitationNotFound for
// any other id.
func (a *Client) AcceptRemoteInvitation(ctx context.Context, v auth.Verified, id string) (iam.Role, error) {
	return a.engine.AcceptRemoteInvitation(ctx, v, id)
}

// RemoteUserRoles are the roles trusted issuers' users hold in the group
// ref.
func (a *Client) RemoteUserRoles(ctx context.Context, ref iam.GroupRef) ([]iam.RemoteUserRole, error) {
	return a.ops.RemoteUserRoles(ctx, ref)
}

// RemoveRemoteUserRole ends the role a trusted issuer's user holds in the
// group ref, as who: <persona>:members:manage and coverage of the role.
func (a *Client) RemoveRemoteUserRole(ctx context.Context, who auth.Identity, ref iam.GroupRef, remoteUserID string, opts ...Option) error {
	return a.ops.RemoveRemoteUserRole(ctx, who, ref, remoteUserID, opts...)
}
