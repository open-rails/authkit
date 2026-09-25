package embedded

import (
	"context"
	"errors"
	"strings"

	"github.com/jackc/pgx/v5"
	authkit "github.com/open-rails/authkit"
	"github.com/open-rails/authkit/internal/db"
	"github.com/open-rails/authkit/verify"
)

// Replacing an application's keys, issuer trust source, slug or enabled state is
// acting as that application: whoever controls its keys holds its role. A group
// actor therefore needs credentials:manage AND coverage of the application's
// current role, exactly as if granting that role. Domain-proven applications
// change their trust only through a new domain proof (ak#392).

// UpsertRemoteApplicationFromClaims registers or updates an application
// controlled by group for the verified request actor.
func (s *engine) UpsertRemoteApplicationFromClaims(ctx context.Context, claims verify.Claims, group authkit.GroupRef, in RemoteApplication) (*RemoteApplication, error) {
	actor, err := groupActorFromClaims(claims)
	if err != nil {
		return nil, err
	}
	if err := s.requirePG(); err != nil {
		return nil, err
	}
	gid, err := s.resolveGroupID(ctx, s.groupStore(), group)
	if err != nil {
		return nil, err
	}
	in.PermissionGroupID = gid
	if s.reservedIssuer(in.Issuer) || s.accountPeerIssuer(in.Issuer) {
		return nil, ErrReservedIssuer
	}
	var out *RemoteApplication
	err = s.withAuthorityMutation(ctx, func(st *PermissionGroupStore) error {
		if err := lockPermissionGroup(ctx, st.q, gid); err != nil {
			return err
		}
		existing, err := db.New(st.q).RemoteApplicationByIssuer(ctx, strings.TrimSpace(in.Issuer))
		bound := false
		switch {
		case errors.Is(err, pgx.ErrNoRows):
			if err := s.authorizeApplicationControl(ctx, st, group.Persona, gid, actor, ""); err != nil {
				return err
			}
			bound = true
		case err != nil:
			return err
		case existing.PermissionGroupID != gid:
			return ErrRemoteApplicationIssuerConflict
		default:
			if err := s.authorizeApplicationControl(ctx, st, group.Persona, gid, actor, existing.ID); err != nil {
				return err
			}
			if existing.TrustRoot == "domain" {
				return ErrInsufficientRoleAuthority
			}
		}
		out, err = s.upsertRemoteApplication(ctx, st, in)
		if err != nil || !bound {
			return err
		}
		// A session-bound issuer is unproven; a later domain proof reclaims it.
		if _, err := st.q.Exec(ctx, `UPDATE remote_applications SET trust_root=$2 WHERE id=$1::uuid`, out.ID, ApplicationTrustRootUser); err != nil {
			return err
		}
		out.TrustRoot = ApplicationTrustRootUser
		return nil
	})
	return out, err
}

// DeleteRemoteApplicationFromClaims deletes the application named by slug when
// group controls it and the request actor covers its role.
func (s *engine) DeleteRemoteApplicationFromClaims(ctx context.Context, claims verify.Claims, group authkit.GroupRef, slug string) error {
	actor, err := groupActorFromClaims(claims)
	if err != nil {
		return err
	}
	if err := s.requirePG(); err != nil {
		return err
	}
	slug = strings.ToLower(strings.TrimSpace(slug))
	if slug == "" {
		return ErrInvalidRemoteApplication
	}
	gid, err := s.resolveGroupID(ctx, s.groupStore(), group)
	if err != nil {
		return err
	}
	return s.withAuthorityMutation(ctx, func(st *PermissionGroupStore) error {
		if err := lockPermissionGroup(ctx, st.q, gid); err != nil {
			return err
		}
		q := db.New(st.q)
		app, err := q.RemoteApplicationBySlugForUpdate(ctx, slug)
		if errors.Is(err, pgx.ErrNoRows) || err == nil && app.PermissionGroupID != gid {
			return ErrRemoteApplicationNotFound
		}
		if err != nil {
			return err
		}
		if err := s.authorizeApplicationControl(ctx, st, group.Persona, gid, actor, app.ID); err != nil {
			return err
		}
		if err := s.refuseSubjectOwnerLoss(ctx, st, authkit.RemoteAppSubject(app.ID)); err != nil {
			return err
		}
		_, err = q.RemoteApplicationDelete(ctx, app.Issuer)
		return err
	})
}

// authorizeApplicationControl requires credentials:manage in gid, plus coverage
// of the role appID currently holds there (none for a new application).
func (s *engine) authorizeApplicationControl(ctx context.Context, st *PermissionGroupStore, persona authkit.Persona, gid string, actor groupMutationActor, appID string) error {
	sch := s.groupSchemaOrDefault()
	capability := PermCredentialsManage(persona)
	if appID != "" {
		role, err := st.directRole(ctx, gid, authkit.RemoteAppSubject(appID))
		if err != nil {
			return err
		}
		if role != "" {
			return s.authorizeGroupActorRole(ctx, st, sch, persona, gid, actor, capability, role)
		}
	}
	subject, err := s.groupMutationSubject(ctx, st, persona, gid, actor)
	if err != nil {
		return err
	}
	asg, resolver, err := st.assignmentsWithCustomRoles(ctx, gid, subject, true)
	if err != nil {
		return err
	}
	if !anyGrantCovers(sch.ResolveGrants(asg, resolver), capability) || (actor.remote != nil && !actor.remote.HasPermission(capability)) {
		return ErrInsufficientRoleAuthority
	}
	return nil
}
