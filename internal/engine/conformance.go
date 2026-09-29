package engine

import (
	"github.com/open-rails/authkit/internal/httpapi"
	"github.com/open-rails/authkit/verify"
)

// Compile-time proof the engine drives the HTTP layer and verify's
// enrichment, permission, session and federation seams.
var (
	_ httpapi.Backend                = (*Engine)(nil)
	_ verify.Enricher                = (*Engine)(nil)
	_ verify.RemoteApplicationSource = (*Engine)(nil)
	_ verify.PermissionChecker       = (*Engine)(nil)
	_ verify.SessionChecker          = (*Engine)(nil)
)
