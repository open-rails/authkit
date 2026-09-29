package engine

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/jackc/pgx/v5"
	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/internal/db"
	"github.com/open-rails/authkit/internal/errmodel"
	"github.com/open-rails/authkit/internal/ident"
)

// Controlling an application's keys is acting as it, so every non-system
// change to an existing application needs CAP(<persona>:credentials:manage)
// in its controlling group and COVER of every role it holds anywhere. Only
// applications a group registered (trust root user) change through a group:
// system-registered ones rotate through the system and domain-rooted ones
// through a new domain proof. A group registration starts unapproved (tier
// registered), and so does any re-key of it.
//
// A group registration is a credential (rule CRED, credential_issuers.go):
// only a user registers one, the user who supplies its keys is its registrar,
// and its roles never outlive the registrar's authority.

// UpsertRemoteApplication registers the application app.Issuer in the group
// ref, or updates it there. The system may set Mode, Tier and TrustRoot
// (new applications default to manual and approved); a user registers at
// trust root user and tier registered. Machine actors cannot register.
func (s *Engine) UpsertRemoteApplication(ctx context.Context, actor iam.Actor, ref iam.GroupRef, in iam.RemoteApplication) (*iam.RemoteApplication, error) {
	if err := requireActor(actor); err != nil {
		return nil, err
	}
	if err := s.requirePG(); err != nil {
		return nil, err
	}
	system := actor.Kind() == iam.ActorSystem
	if _, err := credentialIssuer(actor); err != nil {
		return nil, err
	}
	in.Issuer = strings.TrimSpace(in.Issuer)
	if s.reservedIssuer(in.Issuer) || !system && s.accountPeerIssuer(in.Issuer) {
		return nil, iam.ErrReservedIssuer
	}
	if !validTier(in.Tier) || !validTrustRoot(in.TrustRoot) {
		return nil, fmt.Errorf("%w: unknown tier or trust root", iam.ErrInvalidRemoteApplication)
	}
	var out *iam.RemoteApplication
	err := s.withGroupMutation(ctx, actor, ref, func(st *permissionGroupStore, g groupTarget) error {
		in.PermissionGroupID = g.ID
		row, err := db.New(st.q).RemoteApplicationByIssuer(ctx, in.Issuer)
		var existing *iam.RemoteApplication
		switch {
		case errors.Is(err, pgx.ErrNoRows):
		case err != nil:
			return err
		case row.PermissionGroupID != g.ID:
			return iam.ErrRemoteApplicationIssuerConflict
		default:
			existing = remoteAppFromRow(remoteAppRow(row))
		}
		rekey := false
		if !system {
			if rekey, err = s.groupApplicationChange(ctx, st, actor, g, existing, &in); err != nil {
				return err
			}
		}
		if out, err = s.upsertRemoteApplication(ctx, st, in); err != nil || !rekey {
			return err
		}
		_, err = st.q.Exec(ctx, `UPDATE remote_applications SET registered_by=$2::uuid WHERE id=$1::uuid`, out.ID, actor.ID())
		return err
	})
	return out, err
}

// groupApplicationChange authorizes a non-system upsert and sets the trust
// root and tier it produces; the caller's Tier and TrustRoot are ignored.
// rekey reports whether the actor supplies new keys, becoming the registrar.
func (s *Engine) groupApplicationChange(ctx context.Context, st *permissionGroupStore, actor iam.Actor, g groupTarget, existing *iam.RemoteApplication, in *iam.RemoteApplication) (rekey bool, err error) {
	appID := ""
	if existing != nil {
		if existing.TrustRoot != iam.ApplicationTrustRootUser {
			return false, iam.ErrInsufficientAuthority
		}
		appID = existing.ID
	}
	if err := s.authorizeApplicationControl(ctx, st, actor, g, appID); err != nil {
		return false, err
	}
	in.TrustRoot, in.Tier = iam.ApplicationTrustRootUser, iam.ApplicationTierRegistered
	if existing != nil && !rekeys(existing, in) {
		in.Tier = existing.Tier
		return false, nil
	}
	return true, nil
}

// rekeys reports whether in replaces existing's trust source.
func rekeys(existing *iam.RemoteApplication, in *iam.RemoteApplication) bool {
	mode, err := normalizeRemoteAppTrustSource(in.JWKSURI, in.Mode, in.PublicKeys, trustSourcePolicy{AllowPrivateNetworkJWKS: true})
	if err != nil || mode != existing.Mode || strings.TrimSpace(in.JWKSURI) != existing.JWKSURI {
		return true
	}
	a, _ := json.Marshal(in.PublicKeys)
	b, _ := json.Marshal(existing.PublicKeys)
	return string(a) != string(b)
}

// DeleteRemoteApplication deletes the application named by slug that group ref
// controls. Any actor but the system needs the same authority as re-keying it, and never
// deletes a system-registered application.
func (s *Engine) DeleteRemoteApplication(ctx context.Context, actor iam.Actor, ref iam.GroupRef, slug string) error {
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
	return s.withGroupMutation(ctx, actor, ref, func(st *permissionGroupStore, g groupTarget) error {
		q := db.New(st.q)
		app, err := q.RemoteApplicationBySlugForUpdate(ctx, slug)
		if errors.Is(err, pgx.ErrNoRows) || err == nil && app.PermissionGroupID != g.ID {
			return iam.ErrRemoteApplicationNotFound
		}
		if err != nil {
			return err
		}
		if actor.Kind() != iam.ActorSystem {
			if iam.ApplicationTrustRoot(app.TrustRoot) == iam.ApplicationTrustRootManual {
				return iam.ErrInsufficientAuthority
			}
			if err := s.authorizeApplicationControl(ctx, st, actor, g, app.ID); err != nil {
				return err
			}
		}
		if err := s.refuseSubjectOwnerLoss(ctx, st, iam.RemoteApplicationSubject(app.ID)); err != nil {
			return err
		}
		_, err = q.RemoteApplicationDelete(ctx, app.Issuer)
		return err
	})
}

// authorizeApplicationControl is CAP(<persona>:credentials:manage) in g plus,
// for an existing application, COVER of every role it holds in any live
// group: whoever controls its keys holds all of them.
func (s *Engine) authorizeApplicationControl(ctx context.Context, st *permissionGroupStore, actor iam.Actor, g groupTarget, appID string) error {
	auth, err := s.actorAuthority(ctx, st, actor, g)
	if err != nil {
		return err
	}
	if err := auth.requireCap(iam.PermCredentialsManage(g.Persona)); err != nil || appID == "" {
		return err
	}
	type held struct {
		group groupTarget
		role  iam.Role
	}
	rows, err := st.q.Query(ctx, `SELECT g.id::text, g.persona, r.role FROM group_remote_application_roles r
 JOIN permission_groups g ON g.id=r.permission_group_id
 WHERE r.remote_application_id=$1::uuid AND g.deleted_at IS NULL ORDER BY g.id`, appID)
	if err != nil {
		return err
	}
	var roles []held
	for rows.Next() {
		var h held
		var role string
		if err := rows.Scan(&h.group.ID, scanPersona(&h.group.Persona), &role); err != nil {
			rows.Close()
			return err
		}
		h.role = ident.Role(h.group.Persona, role)
		roles = append(roles, h)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}
	for _, h := range roles {
		in := auth
		if h.group.ID != g.ID {
			if in, err = s.actorAuthority(ctx, st, actor, h.group); err != nil {
				return err
			}
		}
		if err := s.requireRoleCover(ctx, st, in, h.group, h.role); err != nil && !errors.Is(err, iam.ErrRoleNotAssignable) {
			return err
		}
	}
	return nil
}

func validTier(t iam.ApplicationTier) bool {
	return t == "" || t == iam.ApplicationTierRegistered || t == iam.ApplicationTierApproved
}

func validTrustRoot(t iam.ApplicationTrustRoot) bool {
	switch t {
	case "", iam.ApplicationTrustRootManual, iam.ApplicationTrustRootDomain, iam.ApplicationTrustRootUser:
		return true
	}
	return false
}

// RemoteApplications lists the applications group ref controls, newest first.
func (s *Engine) RemoteApplications(ctx context.Context, ref iam.GroupRef, page iam.PageRequest) (iam.ListPage[iam.RemoteApplication], error) {
	var out iam.ListPage[iam.RemoteApplication]
	if err := s.requirePG(); err != nil {
		return out, err
	}
	var after *string
	if page.Cursor != "" {
		raw, err := base64.RawURLEncoding.DecodeString(page.Cursor)
		id := string(raw)
		if err != nil || !isUUID(id) {
			return out, fmt.Errorf("%w: invalid cursor", errmodel.E(errmodel.CodeInvalidRequest))
		}
		after = &id
	}
	st := s.groupStore()
	g, err := s.resolveGroup(ctx, st, ref)
	if err != nil {
		return out, err
	}
	limit := page.PageLimit()
	rows, err := s.pg.Query(ctx,
		`SELECT id::text, slug, permission_group_id::text, issuer, jwks_uri, mode, public_keys, enabled,
		        display_name, tier, trust_root, domain, document_endpoint, root_verified_at, created_at, updated_at
		 FROM remote_applications
		 WHERE permission_group_id = $1::uuid AND ($2::uuid IS NULL OR id < $2::uuid)
		 ORDER BY id DESC LIMIT $3`, g.ID, after, limit+1)
	if err != nil {
		return out, err
	}
	defer rows.Close()
	out.Items = make([]iam.RemoteApplication, 0, limit)
	for rows.Next() {
		var row remoteAppRow
		if err := rows.Scan(&row.ID, &row.Slug, &row.PermissionGroupID, &row.Issuer, &row.JwksUri, &row.Mode,
			&row.PublicKeys, &row.Enabled, &row.DisplayName, &row.Tier, &row.TrustRoot, &row.Domain,
			&row.DocumentEndpoint, &row.RootVerifiedAt, &row.CreatedAt, &row.UpdatedAt); err != nil {
			return out, err
		}
		out.Items = append(out.Items, *remoteAppFromRow(row))
	}
	if err := rows.Err(); err != nil {
		return out, err
	}
	if len(out.Items) > limit {
		out.Items = out.Items[:limit]
		out.Next = base64.RawURLEncoding.EncodeToString([]byte(out.Items[limit-1].ID))
	}
	return out, nil
}
