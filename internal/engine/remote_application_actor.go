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
	"github.com/open-rails/authkit/internal/ops"
)

// Controlling an application's keys is acting as it, so every non-system
// change to an existing application needs CAP(<persona>:credentials:manage)
// in its controlling group and COVER of every role it holds anywhere. Only
// applications a group registered (trust root user) change through a group:
// system-registered ones change only through the system.
//
// A group registration is a credential (rule CRED, credential_issuers.go):
// only a user registers one, the user who supplies its keys is its registrar,
// and its roles never outlive the registrar's authority.

// UpsertRemoteApplication registers the application app.Issuer in the group
// ref, or updates it there. The system may set Mode and TrustRoot (new
// applications default to manual); a user registers at trust root user.
// Machine actors cannot register.
func (s *Engine) UpsertRemoteApplication(ctx context.Context, actor iam.Actor, ref iam.GroupRef, in iam.RemoteApplication, opts ...ops.Option) (iam.RemoteApplication, error) {
	host, err := hostTx("UpsertRemoteApplication", opts)
	if err != nil {
		return iam.RemoteApplication{}, err
	}
	if err := requireActor(actor); err != nil {
		return iam.RemoteApplication{}, err
	}
	if err := s.requirePG(); err != nil {
		return iam.RemoteApplication{}, err
	}
	system := actor.Kind() == iam.ActorSystem
	if _, err := credentialIssuer(actor); err != nil {
		return iam.RemoteApplication{}, err
	}
	in.Issuer = strings.TrimSpace(in.Issuer)
	if s.reservedIssuer(in.Issuer) || !system && s.accountPeerIssuer(in.Issuer) {
		return iam.RemoteApplication{}, iam.ErrReservedIssuer
	}
	if !validTrustRoot(in.TrustRoot) {
		return iam.RemoteApplication{}, fmt.Errorf("%w: unknown trust root", iam.ErrInvalidRemoteApplication)
	}
	var out *iam.RemoteApplication
	err = s.withGroupMutationIn(ctx, actor, host, ref, func(st *permissionGroupStore, g groupTarget) error {
		in.GroupID = g.ID
		row, err := db.New(st.q).RemoteApplicationByIssuer(ctx, in.Issuer)
		var existing *iam.RemoteApplication
		switch {
		case errors.Is(err, pgx.ErrNoRows):
		case err != nil:
			return err
		case row.PermissionGroupID != g.ID:
			return iam.ErrRemoteApplicationIssuerConflict
		default:
			existing = remoteAppFromRow(row)
		}
		rekey := false
		if !system {
			if rekey, err = s.groupApplicationChange(ctx, st, actor, g, existing, &in); err != nil {
				return err
			}
		}
		if out, err = s.upsertRemoteApplication(ctx, st, in); err != nil {
			return err
		}
		if rekey {
			if err := db.New(st.q).RemoteApplicationSetRegistrar(ctx, db.RemoteApplicationSetRegistrarParams{ID: out.ID, RegisteredBy: actor.ID(), CatalogIssuer: s.cfg.Token.Issuer}); err != nil {
				return err
			}
		}
		apps := []iam.RemoteApplication{*out}
		if err := s.loadApplicationRoles(ctx, st.q, g.ID, apps); err != nil {
			return err
		}
		*out = apps[0]
		return nil
	})
	if err != nil {
		return iam.RemoteApplication{}, err
	}
	return *out, nil
}

// groupApplicationChange authorizes a non-system upsert and sets its trust
// root to user; the caller's TrustRoot is ignored. rekey reports whether the
// actor supplies new keys, becoming the registrar.
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
	in.TrustRoot = iam.ApplicationTrustRootUser
	return existing == nil || rekeys(existing, in), nil
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

// DeleteRemoteApplication deletes the application id that group ref
// controls; an id unknown in the group is iam.ErrRemoteApplicationNotFound.
// Any actor but the system needs the same authority as re-keying it, and
// never deletes a system-registered application.
func (s *Engine) DeleteRemoteApplication(ctx context.Context, actor iam.Actor, ref iam.GroupRef, id string, opts ...ops.Option) error {
	host, err := hostTx("DeleteRemoteApplication", opts)
	if err != nil {
		return err
	}
	if err := requireActor(actor); err != nil {
		return err
	}
	if err := s.requirePG(); err != nil {
		return err
	}
	id = strings.TrimSpace(id)
	return s.withGroupMutationIn(ctx, actor, host, ref, func(st *permissionGroupStore, g groupTarget) error {
		if !isUUID(id) {
			return iam.ErrRemoteApplicationNotFound
		}
		q := db.New(st.q)
		app, err := q.RemoteApplicationByIDForUpdate(ctx, id)
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
	if err := auth.requireCap(ident.CredentialsManage(g.Persona)); err != nil || appID == "" {
		return err
	}
	held, err := db.New(st.q).RemoteApplicationControlRoles(ctx, appID)
	if err != nil {
		return err
	}
	for _, h := range held {
		group := groupTarget{ID: h.GroupID, Persona: ident.Persona(h.Persona)}
		in := auth
		if group.ID != g.ID {
			if in, err = s.actorAuthority(ctx, st, actor, group); err != nil {
				return err
			}
		}
		if err := s.requireRoleCover(ctx, st, in, group, ident.RoleText(h.Role)); err != nil && !errors.Is(err, iam.ErrRoleNotAssignable) {
			return err
		}
	}
	return nil
}

func validTrustRoot(t iam.ApplicationTrustRoot) bool {
	return t == "" || t == iam.ApplicationTrustRootManual || t == iam.ApplicationTrustRootUser
}

// ListRemoteApplications lists the applications group ref controls, newest
// first, with their roles.
func (s *Engine) ListRemoteApplications(ctx context.Context, ref iam.GroupRef, page iam.PageRequest) (iam.ListPage[iam.RemoteApplication], error) {
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
	rows, err := s.q.RemoteApplicationsByGroup(ctx, db.RemoteApplicationsByGroupParams{PermissionGroupID: g.ID, AfterID: after, MaxRows: int64(limit + 1)})
	if err != nil {
		return out, err
	}
	out.Items = make([]iam.RemoteApplication, 0, limit)
	for _, row := range rows {
		out.Items = append(out.Items, *remoteAppFromRow(row))
	}
	if len(out.Items) > limit {
		out.Items = out.Items[:limit]
		out.Next = base64.RawURLEncoding.EncodeToString([]byte(out.Items[limit-1].ID))
	}
	return out, s.loadApplicationRoles(ctx, s.pg, g.ID, out.Items)
}
