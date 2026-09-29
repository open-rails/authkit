package embedded

import (
	"context"

	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/verify"
)

// clientView exposes only application operations, even to type assertions. It
// borrows the runtime; creating a view starts no resources or background work.
type clientView struct{ iam.Client }

// Client returns the engine-free operation view. Runtime retains ownership of
// configuration, signing dependencies, HTTP and lifecycle.
func (s *engine) Client() iam.Client {
	if s == nil {
		return nil
	}
	return clientView{Client: s}
}

// DelegatedPermissionLive makes the view a verify.DelegatedAuthority, so a host
// passing it as its permission checker re-checks delegated tokens this runtime
// minted against their subject's live authority.
func (c clientView) DelegatedPermissionLive(ctx context.Context, cl verify.Claims, perm iam.Perm) (bool, error) {
	return c.Client.(*engine).DelegatedPermissionLive(ctx, cl, perm)
}
