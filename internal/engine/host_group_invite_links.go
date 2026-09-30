package engine

// Invite links (#134/#147): a high-entropy, unbound, single-use code for a
// group role. A signed-in user who redeems it gets the role; possession of the
// link is the credential. The code is returned once; only its sha256 is
// stored. Minting needs invited self-registration (externalInvitesEnabled): a
// stranger can join only if they can obtain an account. Issuance follows rule
// CRED (credential_issuers.go).

import (
	"context"
	"errors"
	"net/url"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/internal/authflow"
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
	mode, err := normalizeRegistrationMode(s.cfg.Registration.NativeUserMode)
	if err != nil {
		return false
	}
	return mode == iam.RegistrationModeOpen || mode == iam.RegistrationModeInviteOnly
}

// inviteURL builds the host-facing accept-invite link: BaseURL + the configured
// Frontend.InvitePath + #code=. The fragment never reaches a server; the SPA
// reads the code and POSTs it to redeem.
func (s *Engine) inviteURL(code string) string {
	q := url.Values{}
	q.Set("code", code)
	return s.authkitURL(s.cfg.Frontend.InvitePath, q)
}

// requireIssuableRole refuses a role that is not in the group's catalog.
func (s *Engine) requireIssuableRole(ctx context.Context, st *permissionGroupStore, g groupTarget, role iam.Role) ([]string, error) {
	if err := s.requireDefinedGroupRole(ctx, st, g.ID, g.Persona, role); err != nil {
		return nil, err
	}
	return s.roleGrants(ctx, st, g, role)
}

// CreateInviteLink mints a single-use link granting l.Role in ref:
// CAP(<p>:members:manage) plus COVER(role). Only a user or the system issues
// credentials. The code is returned once.
func (s *Engine) CreateInviteLink(ctx context.Context, a iam.Actor, ref iam.GroupRef, l iam.NewInviteLink) (iam.InviteLinkCreated, error) {
	creator, err := credentialIssuer(a)
	if err != nil {
		return iam.InviteLinkCreated{}, err
	}
	if !s.externalInvitesEnabled() {
		return iam.InviteLinkCreated{}, iam.ErrExternalInvitesDisabled
	}
	role := l.Role
	if role.IsZero() {
		return iam.InviteLinkCreated{}, errmodel.ErrInvalidInvite
	}
	ttl := l.ExpiresIn
	if ttl <= 0 {
		ttl = defaultGroupInviteTTL
	}
	out := iam.InviteLinkCreated{Code: secret.Token(32), ExpiresAt: time.Now().UTC().Add(min(ttl, maxGroupInviteTTL))}
	err = s.withGroupMutation(ctx, a, ref, func(st *permissionGroupStore, g groupTarget) error {
		if _, err := s.requireIssuableRole(ctx, st, g, role); err != nil {
			return err
		}
		if err := s.requireRoleGrant(ctx, st, a, g, iam.PermMembersManage(g.Persona), role); err != nil {
			return err
		}
		id, err := db.New(st.q).InviteLinkInsert(ctx, db.InviteLinkInsertParams{
			GroupID: g.ID, Role: role.Name(), InvitedBy: nullable(creator), CodeHash: secret.Hash(out.Code), ExpiresAt: out.ExpiresAt,
		})
		out.ID = id
		return err
	})
	if err != nil {
		return iam.InviteLinkCreated{}, err
	}
	out.URL = s.inviteURL(out.Code)
	return out, nil
}

// InviteLinks lists the group's links, newest first, active or not. Never the
// code or its hash.
func (s *Engine) InviteLinks(ctx context.Context, ref iam.GroupRef, p iam.PageRequest) (iam.ListPage[iam.InviteLink], error) {
	if err := s.requirePG(); err != nil {
		return iam.ListPage[iam.InviteLink]{}, err
	}
	after, err := idCursor(p)
	if err != nil {
		return iam.ListPage[iam.InviteLink]{}, err
	}
	st := s.groupStore()
	g, err := s.resolveGroup(ctx, st, ref)
	if err != nil {
		return iam.ListPage[iam.InviteLink]{}, err
	}
	rows, err := db.New(st.q).InviteLinksByGroup(ctx, db.InviteLinksByGroupParams{GroupID: g.ID, After: after, PageLimit: int64(p.PageLimit() + 1)})
	if err != nil {
		return iam.ListPage[iam.InviteLink]{}, err
	}
	links := make([]iam.InviteLink, len(rows))
	for i, r := range rows {
		links[i] = iam.InviteLink{
			ID: r.ID, Role: ident.Role(g.Persona, r.Role), InvitedBy: r.InvitedBy, CreatedAt: r.CreatedAt,
			ExpiresAt: r.ExpiresAt, RedeemedAt: r.RedeemedAt, RevokedAt: r.RevokedAt,
		}
	}
	return idPage(links, p.PageLimit(), func(l iam.InviteLink) string { return l.ID }), nil
}

// RevokeInviteLink revokes the group's live link: CAP(<p>:members:manage) plus
// COVER of the link's role. ErrInviteLinkNotFound when none matches.
func (s *Engine) RevokeInviteLink(ctx context.Context, a iam.Actor, ref iam.GroupRef, linkID string) error {
	if err := requireActor(a); err != nil {
		return err
	}
	linkID = strings.TrimSpace(linkID)
	return s.withGroupMutation(ctx, a, ref, func(st *permissionGroupStore, g groupTarget) error {
		if !isUUID(linkID) {
			return iam.ErrInviteLinkNotFound
		}
		q := db.New(st.q)
		name, err := q.InviteLinkRoleForUpdate(ctx, db.InviteLinkRoleForUpdateParams{ID: linkID, GroupID: g.ID})
		if errors.Is(err, pgx.ErrNoRows) {
			return iam.ErrInviteLinkNotFound
		}
		if err != nil {
			return err
		}
		if err := s.requireCredentialRevoke(ctx, st, a, g, iam.PermMembersManage(g.Persona), ident.Role(g.Persona, name)); err != nil {
			return err
		}
		return q.InviteLinkRetire(ctx, linkID)
	})
}

// RedeemInviteLink redeems code for the signed-in user a: the link must be
// live (not revoked, expired or used) and its issuer live, and the redeemer
// live. The role is assigned in the same transaction and the link consumed.
// Idempotent: a redeemer already holding the role succeeds without using it.
// code may also be a role-carrying account invitation (an add by email): only
// the account that has verified the invited address accepts it.
func (s *Engine) RedeemInviteLink(ctx context.Context, a iam.Actor, code string) (authflow.InviteRedemption, error) {
	var out authflow.InviteRedemption
	code = strings.TrimSpace(code)
	if a.Kind() != iam.ActorUser || !isUUID(a.ID()) {
		return out, iam.ErrInsufficientAuthority
	}
	if code == "" {
		return out, errmodel.ErrInvalidInvite
	}
	redeemer := iam.UserSubject(a.ID())
	codeHash := secret.Hash(code)
	err := s.withAuthorityMutation(ctx, a, func(st *permissionGroupStore) error {
		q := db.New(st.q)
		groupID, err := q.InviteLinkGroupByCode(ctx, codeHash)
		if errors.Is(err, pgx.ErrNoRows) {
			return s.acceptAccountInvite(ctx, st, redeemer, codeHash, &out)
		}
		if err != nil {
			return err
		}
		if err := lockPermissionGroup(ctx, st.q, groupID); err != nil {
			return err
		}
		link, err := q.InviteLinkByCodeForUpdate(ctx, db.InviteLinkByCodeForUpdateParams{CodeHash: codeHash, GroupID: groupID})
		if errors.Is(err, pgx.ErrNoRows) {
			return iam.ErrInviteLinkNotFound
		}
		if err != nil {
			return err
		}
		out.GroupID, out.Persona = link.GroupID, ident.Persona(link.Persona)
		out.Role = ident.Role(out.Persona, link.Role)
		if link.RevokedAt != nil || !link.IssuerLive {
			return errmodel.ErrInviteLinkRevoked
		}
		if link.ExpiresAt != nil && !link.ExpiresAt.After(time.Now().UTC()) {
			return errmodel.ErrInviteLinkExpired
		}
		live, err := subjectUsable(ctx, st.q, redeemer)
		if err != nil {
			return err
		}
		if !live {
			return iam.ErrInsufficientAuthority
		}
		already, err := subjectHasRole(ctx, st.q, groupID, redeemer.ID, out.Role)
		if err != nil || already {
			return err
		}
		if link.RedeemedAt != nil {
			return iam.ErrInviteLinkNotFound
		}
		if err := s.assignInvitedRole(ctx, st, groupID, out.Persona, redeemer.ID, out.Role); err != nil {
			return err
		}
		return q.InviteLinkRedeem(ctx, link.ID)
	})
	if err != nil {
		return authflow.InviteRedemption{}, err
	}
	return out, nil
}

// acceptAccountInvite accepts a role-carrying account invitation for an
// existing account: the redeemer's verified email must be the invited address,
// so the role lands only with the consent of whoever proved it. Anything else
// is ErrInviteLinkNotFound, never a hint about the invitation.
func (s *Engine) acceptAccountInvite(ctx context.Context, st *permissionGroupStore, redeemer iam.Subject, codeHash string, out *authflow.InviteRedemption) error {
	q := db.New(st.q)
	groupID, err := q.AccountInviteGroupByCode(ctx, codeHash)
	if errors.Is(err, pgx.ErrNoRows) {
		return iam.ErrInviteLinkNotFound
	}
	if err != nil {
		return err
	}
	if err := lockPermissionGroup(ctx, st.q, groupID); err != nil {
		return err
	}
	invite, err := q.AccountInviteByCodeForUpdate(ctx, db.AccountInviteByCodeForUpdateParams{CodeHash: codeHash, GroupID: groupID, UserID: redeemer.ID})
	if errors.Is(err, pgx.ErrNoRows) || err == nil && !invite.Addressed {
		return iam.ErrInviteLinkNotFound
	}
	if err != nil {
		return err
	}
	out.GroupID, out.Persona = invite.GroupID, ident.Persona(invite.Persona)
	out.Role = ident.Role(out.Persona, invite.Role)
	if invite.RevokedAt != nil || !invite.IssuerLive {
		return errmodel.ErrInviteLinkRevoked
	}
	if !invite.ExpiresAt.After(time.Now().UTC()) {
		return errmodel.ErrInviteLinkExpired
	}
	live, err := subjectUsable(ctx, st.q, redeemer)
	if err != nil {
		return err
	}
	if !live {
		return iam.ErrInsufficientAuthority
	}
	already, err := subjectHasRole(ctx, st.q, groupID, redeemer.ID, out.Role)
	if err != nil || already {
		return err
	}
	if invite.ConsumedAt != nil {
		return iam.ErrInviteLinkNotFound
	}
	if err := s.assignInvitedRole(ctx, st, groupID, out.Persona, redeemer.ID, out.Role); err != nil {
		return err
	}
	return q.AccountInviteConsume(ctx, db.AccountInviteConsumeParams{ID: invite.ID, UserID: redeemer.ID})
}

// subjectHasRole reports whether the user already holds role in the group.
func subjectHasRole(ctx context.Context, q db.DBTX, groupID, userID string, role iam.Role) (bool, error) {
	return db.New(q).GroupUserHasRole(ctx, db.GroupUserHasRoleParams{GroupID: groupID, UserID: userID, Role: role.Name()})
}
