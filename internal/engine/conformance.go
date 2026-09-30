package engine

import (
	"github.com/open-rails/authkit/internal/httpapi"
	"github.com/open-rails/authkit/verify"
)

// Compile-time proof the engine drives the HTTP layer and is the authority
// verify's live gates consume.
var (
	_ httpapi.Backend  = (*Engine)(nil)
	_ verify.Authority = (*Engine)(nil)
)
