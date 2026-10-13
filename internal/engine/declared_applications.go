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

// survivable reports whether err refuses one declared application alone (an
// invalid issuer, trust source or role), as opposed to a database failure.
func survivable(err error) bool {
	var e iam.Error
	return errors.As(err, &e) && e.Status() < 500
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
	// At boot an application the configuration gets wrong is left out, so it
	// is disabled like an undeclared one: only its tokens are refused.
	tolerant := host == nil && source == "Config.RemoteApplications"
	var disabled []string
	var refused []error
	err := s.withGroupMutationIn(ctx, iam.SystemIdentity(), host, ref, func(st *permissionGroupStore, g groupTarget) error {
		disabled, refused = nil, nil
		declared := issuers[:0:0]
		for _, app := range apps {
			apply := func() error { return s.applyDeclaredApplication(ctx, st, g, app) }
			var err error
			if tolerant {
				err = s.applyAlone(ctx, st, apply)
			} else {
				err = apply()
			}
			switch {
			case err == nil:
				declared = append(declared, app.Issuer)
			case tolerant && survivable(err):
				refused = append(refused, fmt.Errorf("authkit: %s %q is disabled, so its tokens are refused: %w", source, app.Issuer, err))
			default:
				return fmt.Errorf("authkit: %s %q: %w", source, app.Issuer, err)
			}
		}
		issuers := declared
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
	if err == nil {
		for _, problem := range refused {
			s.degrade(problem)
		}
		for _, issuer := range disabled {
			slog.InfoContext(ctx, "authkit: disabled a remote application "+source+" no longer declares", "issuer", issuer)
		}
	}
	return err
}

// applyAlone runs apply in a savepoint of st's transaction: a failure rolls
// back its writes alone, so the transaction goes on.
func (s *Engine) applyAlone(ctx context.Context, st *permissionGroupStore, apply func() error) error {
	tx, ok := st.q.(pgx.Tx)
	if !ok {
		return apply()
	}
	sp, err := tx.Begin(ctx)
	if err != nil {
		return err
	}
	touched := len(st.touched)
	st.q = sp
	err = apply()
	st.q = tx
	if err == nil {
		return sp.Commit(ctx)
	}
	if rbErr := sp.Rollback(ctx); rbErr != nil {
		return errors.Join(err, rbErr)
	}
	st.touched = st.touched[:touched]
	return err
}

// applyDeclaredApplication registers app in g, the system's to change, and
// makes app.Role its role there: none when zero. A role of another persona,
// or one needing a second factor (an application presents none), is refused.
func (s *Engine) applyDeclaredApplication(ctx context.Context, st *permissionGroupStore, g groupTarget, app iam.RemoteApplication) error {
	if !app.Role.IsZero() {
		if err := s.requireDefinedGroupRole(ctx, st.q, g, app.Role); err != nil {
			return err
		}
	}
	if err := s.validRoleMap(ctx, st.q, g, app.RoleMap); err != nil {
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
