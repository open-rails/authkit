package authkit

import (
	"context"
	"errors"

	"github.com/open-rails/authkit/iam"
)

// MigrateGroupPersona explicitly translates one existing group's persona and
// grants while retaining its identity, tenant and credentials. This trusted
// host operation is dry-run by default and is never called by startup. Apply
// takes a table lock and requires table-owner privileges. Keep both catalogs
// declared throughout the coordinated maintenance window. The returned report
// calls out signed token claims that need refresh/reissue; they are not edited.
func (a *Client) MigrateGroupPersona(ctx context.Context, in iam.GroupPersonaMigration) (iam.GroupPersonaMigrationReport, error) {
	if a == nil || a.engine == nil {
		return iam.GroupPersonaMigrationReport{}, errors.New("authkit: group persona migration requires a native client")
	}
	return a.engine.MigrateGroupPersona(a.operationContext(ctx), in)
}
