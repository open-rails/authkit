package embedded

import authkit "github.com/open-rails/authkit"

// Compile-time proof the embedded backend satisfies the public authkit.Client
// contract (#138). The assertion lives here, not in root, so root never imports
// embedded and stays pgx-free.
var _ authkit.Client = (*Client)(nil)
