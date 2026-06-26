package embedded

import authkit "github.com/open-rails/authkit"

// Compile-time proof the embedded backend satisfies the public authkit.Client
// contract (#138) and the cross-cutting Authorizer slice (#143). Satisfying
// Client already proves every embedded topic interface (Users, Tokens, ...), so
// only the cross-cutting slice needs its own assertion. The assertions live here,
// not in root, so root never imports embedded and stays pgx-free.
var (
	_ authkit.Client     = (*Client)(nil)
	_ authkit.Authorizer = (*Client)(nil)
)
