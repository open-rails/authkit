package engine

import (
	"context"
	"errors"
	"fmt"
	"log/slog"

	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/internal/db"
)

// reconcileRemoteApplications runs at New under the authority lock when
// Config.RemoteApplications is set. It registers the declared applications on
// root, the system's to change, and disables the ones this app declared at an
// earlier boot and no longer does. Like a role removed from the catalog, a
// removed application keeps its row and its roles and confers nothing; it is
// never deleted, so a config mistake loses no grant. The removal never
// refuses the boot: it logs a group left without a usable owner.
func (s *Engine) reconcileRemoteApplications(ctx context.Context) error {
	declared := s.cfg.RemoteApplications
	if s.pg == nil || declared == nil {
		return nil
	}
	issuers := make([]string, len(declared))
	for i, app := range declared {
		issuers[i] = app.Issuer
		if err := s.requireRootRole(app.RootRole); err != nil {
			return fmt.Errorf("authkit: Config.RemoteApplications %q: %w", app.Issuer, err)
		}
	}
	var disabled []string
	err := s.withAuthorityMutation(ctx, iam.SystemActor(), func(st *permissionGroupStore) error {
		disabled = nil
		rootID, err := s.rootGroup(ctx, st)
		if err != nil {
			return err
		}
		for _, app := range declared {
			err := s.applyRootApplication(ctx, st, iam.RemoteApplication{
				GroupID: rootID, Issuer: app.Issuer, JWKSURI: app.JWKSURI, PublicKeys: app.PublicKeys,
				Enabled: !app.Disabled, TrustRoot: iam.ApplicationTrustRootManual,
			}, app.RootRole)
			if err != nil {
				return fmt.Errorf("authkit: Config.RemoteApplications %q: %w", app.Issuer, err)
			}
		}
		q := db.New(st.q)
		by := s.cfg.Token.Issuer
		if err := q.RemoteApplicationsDeclare(ctx, db.RemoteApplicationsDeclareParams{DeclaredBy: by, Issuers: issuers}); err != nil {
			return err
		}
		removed, err := q.RemoteApplicationsUndeclared(ctx, db.RemoteApplicationsUndeclaredParams{DeclaredBy: by, Issuers: issuers})
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
			slog.InfoContext(ctx, "authkit: disabled a remote application Config.RemoteApplications no longer declares", "issuer", issuer)
		}
	}
	return err
}
