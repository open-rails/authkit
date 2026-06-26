package remote

import authkit "github.com/open-rails/authkit"

// Compile-time proof the remote SDK satisfies the full public authkit.Client
// contract (#142) — the same assertion embedded.Client holds. This is what makes
// the embedded↔remote swap construction-only; it fails to build if codegen and
// the interface drift. The capability slices hold too.
var (
	_ authkit.Client      = (*Client)(nil)
	_ authkit.Authorizer  = (*Client)(nil)
	_ authkit.TokenIssuer = (*Client)(nil)
)
