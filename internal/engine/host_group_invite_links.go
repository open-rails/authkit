package engine

// Invite links (#134/#147): a high-entropy, unbound, single-use code for a
// group role. A signed-in user who redeems it, or a sign-up presenting it,
// gets the role; possession of the link is the credential. The code is
// returned once; only its sha256 is stored. Minting needs invited
// self-registration (externalInvitesEnabled): a stranger joins by signing up
// with it. Issuance follows rule CRED (credential_issuers.go).

import (
	"context"
	"errors"
	"net/url"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/open-rails/authkit/auth"
	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/internal/authflow"
	"github.com/open-rails/authkit/internal/config"
	"github.com/open-rails/authkit/internal/db"
	"github.com/open-rails/authkit/internal/errmodel"
	"github.com/open-rails/authkit/internal/ident"
	"github.com/open-rails/authkit/internal/secret"
)

const (
	defaultGroupInviteTTL = 72 * time.Hour
	// maxGroupInviteTTL caps a link's lifetime (#247): a longer request is
	// clamped, never rejected, bounding a leaked or forgotten link.
	maxGroupInviteTTL = 30 * 24 * time.Hour
)

// externalInvitesEnabled reports whether invite LINKS may be minted. They make
// sense only when AuthKit permits invited self-registration: open (anyone may
// sign up) or invite_only (sign up ONLY via an invite). Under closed an invited
// stranger has no way to obtain an account, so the capability is OFF (an admin
// assigns roles directly via the members endpoint instead).
func (s *Engine) externalInvitesEnabled() bool {
	mode := s.cfg.Registration
	return mode == iam.RegistrationModeOpen || mode == iam.RegistrationModeInviteOnly
}

// inviteURL builds the host-facing accept-invite link: FrontendURL + /invite
// + #link_code=. The fragment never reaches a server; the SPA reads the code
// and POSTs it to redeem. A bare #code= is an OIDC step-up's return.
func (s *Engine) inviteURL(code string) string {
	q := url.Values{}
	q.Set("link_code", code)
	return s.authkitURL(config.InvitePath, q)
}

// RedeemInvitation redeems code for the signed-in user a (redeemInvitation):
// the role is assigned in the same transaction and the link consumed.
// Idempotent: a redeemer already holding the role succeeds without using it.
// code may also be a role-carrying account invitation (an add by email): only
// the account that has verified the invited address accepts it.
func (s *Engine) RedeemInvitation(ctx context.Context, a auth.Identity, code string) (authflow.InviteRedemption, error) {
	var out authflow.InviteRedemption
	code = strings.TrimSpace(code)
	if err := s.invitationsOn(); err != nil {
		return out, err
	}
	if cs := stateOf(a); !cs.IsUser() || !isUUID(cs.ID()) {
		return out, iam.ErrInsufficientAuthority
	}
	if code == "" {
		return out, errmodel.ErrInvalidInvite
	}
	redeemer := iam.UserSubject(stateOf(a).ID())
	codeHash := secret.Hash(code)
	var err error
	ctx, err = s.proofContext(ctx, "invitation", codeHash)
	if err != nil {
		return out, err
	}
	if err := s.requireTenantUser(ctx, s.q, redeemer.ID); err != nil {
		return out, err
	}
	err = s.withAuthorityMutation(ctx, a, func(st *permissionGroupStore) error {
		q := db.New(st.q)
		groupID, err := q.InviteLinkGroupByCode(ctx, db.InviteLinkGroupByCodeParams{TenantID: s.tenantKey(ctx), CodeHash: codeHash})
		if errors.Is(err, pgx.ErrNoRows) {
			return s.acceptAccountInvite(ctx, st, redeemer, codeHash, &out)
		}
		if err != nil {
			return err
		}
		if err := lockPermissionGroup(ctx, st.q, groupID); err != nil {
			return err
		}
		link, err := q.InviteLinkByCodeForUpdate(ctx, db.InviteLinkByCodeForUpdateParams{TenantID: s.tenantKey(ctx), CodeHash: codeHash, GroupID: groupID})
		if errors.Is(err, pgx.ErrNoRows) {
			return iam.ErrInvitationNotFound
		}
		if err != nil {
			return err
		}
		out.GroupID, out.Persona = link.GroupID, ident.Persona(link.Persona)
		out.Role = ident.RoleText(link.Role)
		return s.redeemInvitation(ctx, st, invitation{
			table: "group_invite_links", id: link.ID, group: groupTarget{ID: groupID, Persona: out.Persona}, role: out.Role,
			used: link.RedeemedAt != nil, revoked: link.RevokedAt != nil, issuerLive: link.IssuerLive, expiresAt: link.ExpiresAt,
		}, nativeHolder{s: s, id: redeemer.ID})
	})
	if err != nil {
		return authflow.InviteRedemption{}, err
	}
	return out, nil
}

// acceptAccountInvite accepts a role-carrying account invitation for an
// existing account: the redeemer's verified email must be the invited address,
// so the role lands only with the consent of whoever proved it. Anything else
// is ErrInvitationNotFound, never a hint about the invitation.
func (s *Engine) acceptAccountInvite(ctx context.Context, st *permissionGroupStore, redeemer iam.Subject, codeHash string, out *authflow.InviteRedemption) error {
	q := db.New(st.q)
	groupID, err := q.AccountInviteGroupByCode(ctx, db.AccountInviteGroupByCodeParams{TenantID: s.tenantKey(ctx), CodeHash: codeHash})
	if errors.Is(err, pgx.ErrNoRows) {
		return iam.ErrInvitationNotFound
	}
	if err != nil {
		return err
	}
	if err := lockPermissionGroup(ctx, st.q, groupID); err != nil {
		return err
	}
	invite, err := q.AccountInviteByCodeForUpdate(ctx, db.AccountInviteByCodeForUpdateParams{TenantID: s.tenantKey(ctx), CodeHash: codeHash, GroupID: groupID, UserID: redeemer.ID})
	if errors.Is(err, pgx.ErrNoRows) || err == nil && !invite.Addressed {
		return iam.ErrInvitationNotFound
	}
	if err != nil {
		return err
	}
	out.GroupID, out.Persona = invite.GroupID, ident.Persona(invite.Persona)
	out.Role = ident.RoleText(invite.Role)
	expires := invite.ExpiresAt
	return s.redeemInvitation(ctx, st, invitation{
		table: "account_registration_invites", id: invite.ID, group: groupTarget{ID: groupID, Persona: out.Persona}, role: out.Role,
		used: invite.ConsumedAt != nil, revoked: invite.RevokedAt != nil, issuerLive: invite.IssuerLive, expiresAt: &expires,
	}, nativeHolder{s: s, id: redeemer.ID})
}
