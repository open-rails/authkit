package engine

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"

	"github.com/jackc/pgx/v5"

	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/internal/db"
	"github.com/open-rails/authkit/internal/ops"
)

// Declared remote applications are a host's whole set of the issuers one
// group trusts: Config.RemoteApplications for root, at New, and
// DeclareRemoteApplications for any group once it exists. The system
// registers each (trust root manual) with its declared role in the group, and
// disables the ones this deployment declared there before and no longer
// does. A removed application keeps its row and its roles and confers
// nothing; it is never deleted, so a config mistake loses no grant, and the
// removal never refuses: it logs a group left without a usable owner.

// reconcileRemoteApplications applies Config.RemoteApplications to root at
// New, when it is set.
func (s *Engine) reconcileRemoteApplications(ctx context.Context) error {
	declared := s.cfg.RemoteApplications
	if s.pg == nil || declared == nil {
		return nil
	}
	apps := make([]iam.RemoteApplication, len(declared))
	for i, app := range declared {
		apps[i] = iam.RemoteApplication{Issuer: app.Issuer, JWKSURI: app.JWKSURI, PublicKeys: app.PublicKeys, Enabled: !app.Disabled, Role: app.Role, RoleMap: app.RoleMap}
	}
	return s.declareRemoteApplications(ctx, nil, iam.RootGroup(), apps, "Config.RemoteApplications")
}

// DeclareRemoteApplications makes apps the group ref's declared remote
// applications (Issuer, JWKSURI or PublicKeys, Enabled and Role are read):
// each is registered by the system in ref with Role, its role there (none
// when zero), and the applications this deployment declared in ref before
// and no longer lists are disabled.
func (s *Engine) DeclareRemoteApplications(ctx context.Context, ref iam.GroupRef, apps []iam.RemoteApplication, opts ...ops.Option) error {
	host, err := hostTx("DeclareRemoteApplications", opts)
	if err != nil {
		return err
	}
	if err := s.requirePG(); err != nil {
		return err
	}
	return s.declareRemoteApplications(ctx, host, ref, apps, "DeclareRemoteApplications")
}

func (s *Engine) declareRemoteApplications(ctx context.Context, host pgx.Tx, ref iam.GroupRef, apps []iam.RemoteApplication, source string) error {
	issuers := make([]string, len(apps))
	for i := range apps {
		apps[i].Issuer = strings.TrimSpace(apps[i].Issuer)
		issuers[i] = apps[i].Issuer
		for _, earlier := range issuers[:i] {
			if issuerKey(earlier) == issuerKey(issuers[i]) {
				return fmt.Errorf("authkit: %s declares %q twice: %w", source, issuers[i], iam.ErrInvalidRemoteApplication)
			}
		}
	}
	var disabled []string
	err := s.withGroupMutationIn(ctx, iam.SystemIdentity(), host, ref, func(st *permissionGroupStore, g groupTarget) error {
		disabled = nil
		for _, app := range apps {
			if err := s.applyDeclaredApplication(ctx, st, g, app); err != nil {
				return fmt.Errorf("authkit: %s %q: %w", source, app.Issuer, err)
			}
		}
		q := db.New(st.q)
		by := s.cfg.Token.Issuer
		if err := q.RemoteApplicationsDeclare(ctx, db.RemoteApplicationsDeclareParams{DeclaredBy: by, PermissionGroupID: g.ID, Issuers: issuers}); err != nil {
			return err
		}
		removed, err := q.RemoteApplicationsUndeclared(ctx, db.RemoteApplicationsUndeclaredParams{DeclaredBy: by, PermissionGroupID: g.ID, Issuers: issuers})
		if err != nil || len(removed) == 0 {
			return err
		}
		ids := make([]string, len(removed))
		for i, app := range removed {
			ids[i] = app.ID
			if !app.Enabled {
				continue
			}
			disabled = append(disabled, app.Issuer)
			err := s.refuseSubjectOwnerLoss(ctx, st, iam.RemoteApplicationSubject(app.ID))
			if errors.Is(err, iam.ErrLastOwner) {
				slog.WarnContext(ctx, "authkit: disabling an undeclared remote application leaves a group without a usable owner; assign one (ListGroups with GroupQuery.Ownerless lists them)", "issuer", app.Issuer)
			} else if err != nil {
				return err
			}
		}
		return q.RemoteApplicationsRelease(ctx, ids)
	})
	for _, issuer := range disabled {
		if err == nil {
			slog.InfoContext(ctx, "authkit: disabled a remote application "+source+" no longer declares", "issuer", issuer)
		}
	}
	return err
}

// applyDeclaredApplication registers app in g, the system's to change, and
// makes app.Role its role there: none when zero. A role of another persona,
// or one needing a second factor (an application presents none), is refused.
func (s *Engine) applyDeclaredApplication(ctx context.Context, st *permissionGroupStore, g groupTarget, app iam.RemoteApplication) error {
	if !app.Role.IsZero() && !s.validRoleForPersona(s.groupSchemaOrDefault(), g.Persona, app.Role) {
		return fmt.Errorf("%q is not a role of a %q group: %w", app.Role, g.Persona, iam.ErrRoleNotAssignable)
	}
	if err := s.validRoleMap(g.Persona, app.RoleMap); err != nil {
		return err
	}
	app.GroupID, app.TrustRoot = g.ID, iam.ApplicationTrustRootManual
	ra, err := s.upsertRemoteApplication(ctx, st, app)
	if err != nil {
		return err
	}
	subject := iam.RemoteApplicationSubject(ra.ID)
	if app.Role.IsZero() {
		current, err := st.directRole(ctx, g, subject)
		if err != nil || current.IsZero() {
			return err
		}
		if err := s.refuseOwnerLoss(ctx, st, g.ID, subject); err != nil {
			return err
		}
		return st.UnassignSubject(ctx, g.ID, subject)
	}
	if err := s.requireMFAForRoleAssignment(ctx, st.q, g.ID, g.Persona, subject, app.Role); err != nil {
		return err
	}
	if !app.Role.IsOwner() {
		if err := s.refuseOwnerLoss(ctx, st, g.ID, subject); err != nil {
			return err
		}
	}
	return st.AssignRole(ctx, g.ID, subject, app.Role)
}
