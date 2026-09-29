package authkit

import (
	"github.com/open-rails/authkit/internal/httpapi"
	"github.com/open-rails/authkit/verify"
)

// Compile-time proof the engine drives the HTTP layer and verify's
// enrichment, liveness and federation seams, and that Auth is a permission
// checker hosts can hand to verify.
var (
	_ httpapi.Backend                = (*engine)(nil)
	_ verify.Enricher                = (*engine)(nil)
	_ verify.RemoteApplicationSource = (*engine)(nil)
	_ verify.LivenessSource          = (*Auth)(nil)
	_ verify.PermissionChecker       = (*Auth)(nil)
	_ verify.DelegatedAuthority      = (*Auth)(nil)
)
