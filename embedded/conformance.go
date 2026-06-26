package embedded

import authkit "github.com/open-rails/authkit"

// Compile-time proof the embedded backend satisfies the public authkit.Client
// contract (#138) and the small capability interfaces (#143). The assertions live
// here, not in root, so root never imports embedded and stays pgx-free.
var (
	_ authkit.Client      = (*Client)(nil)
	_ authkit.Authorizer  = (*Client)(nil)
	_ authkit.TokenIssuer = (*Client)(nil)
)
