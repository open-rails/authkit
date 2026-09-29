package authkit

import (
	"context"
	"errors"
	"strings"

	"github.com/jackc/pgx/v5"
	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/internal/db"
)

// Replacing an application's keys, issuer trust source, slug or enabled state is
// acting as that application: whoever controls its keys holds its role. A group
// actor therefore needs credentials:manage AND coverage of the application's
// current role, exactly as if granting that role. Domain-proven applications
// change their trust only through a new domain proof (ak#392).

// UpsertRemoteApplicationForActor registers or updates an application
// controlled by group for actor.
func (s *engine) UpsertRemoteApplicationForActor(ctx context.Context, actor iam.Actor, group iam.GroupRef, in iam.RemoteApplication) (*iam.RemoteApplication, error) {
	if err := requireActor(actor); err != nil {
		return nil, err
	}
	if err := s.requirePG(); err != nil {
		return nil, err
	}
	g, err := s.resolveGroup(ctx, s.groupStore(), group)
	if err != nil {
		return nil, err
	}
	gid := g.ID
	in.PermissionGroupID = gid
	if s.reservedIssuer(in.Issuer) || s.accountPeerIssuer(in.Issuer) {
		return nil, iam.ErrReservedIssuer
	}
	var out *iam.RemoteApplication
	err = s.withAuthorityMutation(ctx, func(st *permissionGroupStore) error {
		if err := lockPermissionGroup(ctx, st.q, gid); err != nil {
			return err
		}
		existing, err := db.New(st.q).RemoteApplicationByIssuer(ctx, strings.TrimSpace(in.Issuer))
		bound := false
		switch {
		case errors.Is(err, pgx.ErrNoRows):
			if err := s.authorizeApplicationControl(ctx, st, actor, g, ""); err != nil {
				return err
			}
			bound = true
		case err != nil:
			return err
		case existing.PermissionGroupID != gid:
			return iam.ErrRemoteApplicationIssuerConflict
		default:
			if err := s.authorizeApplicationControl(ctx, st, actor, g, existing.ID); err != nil {
				return err
			}
			if existing.TrustRoot == "domain" {
				return iam.ErrInsufficientRoleAuthority
			}
		}
		out, err = s.upsertRemoteApplication(ctx, st, in)
		if err != nil || !bound {
			return err
		}
		// A session-bound issuer is unproven; a later domain proof reclaims it.
		if _, err := st.q.Exec(ctx, `UPDATE remote_applications SET trust_root=$2 WHERE id=$1::uuid`, out.ID, iam.ApplicationTrustRootUser); err != nil {
			return err
		}
		out.TrustRoot = iam.ApplicationTrustRootUser
		return nil
	})
	return out, err
}

// DeleteRemoteApplicationForActor deletes the application named by slug when
// group controls it and actor covers its role.
func (s *engine) DeleteRemoteApplicationForActor(ctx context.Context, actor iam.Actor, group iam.GroupRef, slug string) error {
	if err := requireActor(actor); err != nil {
		return err
	}
	if err := s.requirePG(); err != nil {
		return err
	}
	slug = strings.ToLower(strings.TrimSpace(slug))
	if slug == "" {
		return iam.ErrInvalidRemoteApplication
	}
	g, err := s.resolveGroup(ctx, s.groupStore(), group)
	if err != nil {
		return err
	}
	gid := g.ID
	return s.withAuthorityMutation(ctx, func(st *permissionGroupStore) error {
		if err := lockPermissionGroup(ctx, st.q, gid); err != nil {
			return err
		}
		q := db.New(st.q)
		app, err := q.RemoteApplicationBySlugForUpdate(ctx, slug)
		if errors.Is(err, pgx.ErrNoRows) || err == nil && app.PermissionGroupID != gid {
			return iam.ErrRemoteApplicationNotFound
		}
		if err != nil {
			return err
		}
		if err := s.authorizeApplicationControl(ctx, st, actor, g, app.ID); err != nil {
			return err
		}
		if err := s.refuseSubjectOwnerLoss(ctx, st, iam.RemoteApplicationSubject(app.ID)); err != nil {
			return err
		}
		_, err = q.RemoteApplicationDelete(ctx, app.Issuer)
		return err
	})
}

// authorizeApplicationControl requires CAP(<persona>:credentials:manage) in g,
// plus COVER of the role appID currently holds there (none for a new application).
func (s *engine) authorizeApplicationControl(ctx context.Context, st *permissionGroupStore, actor iam.Actor, g groupTarget, appID string) error {
	auth, err := s.actorAuthority(ctx, st, actor, g)
	if err != nil {
		return err
	}
	if err := auth.requireCap(iam.PermCredentialsManage(g.Persona)); err != nil {
		return err
	}
	if appID == "" {
		return nil
	}
	role, err := st.directRole(ctx, g.ID, iam.RemoteApplicationSubject(appID))
	if err != nil || role == "" {
		return err
	}
	return s.requireRoleCover(ctx, st, auth, g, role)
}
