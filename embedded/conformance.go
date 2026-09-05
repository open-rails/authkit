package embedded

import (
	authkit "github.com/open-rails/authkit"
	"github.com/open-rails/authkit/verify"
)

// Compile-time proof the engine satisfies the public authkit.Client contract
// hosts hold (the assertion lives here, not in root, so root never imports
// embedded and stays pgx-free), and verify's enrichment + lazy-load
// federation seams (verifier.WithService / SetRemoteApplicationSource).
var (
	_ authkit.Client                 = (*Client)(nil)
	_ verify.Enricher                = (*Client)(nil)
	_ verify.RemoteApplicationSource = (*Client)(nil)
)
