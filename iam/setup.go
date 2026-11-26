package iam

import (
	"time"

	"github.com/open-rails/authkit/internal/errmodel"
)

// ErrSetupLinkInvalid indicates a setup link that is unknown, used, expired
// or replaced, or one Start issued after someone came to hold a root role.
var ErrSetupLinkInvalid Error = errmodel.E(errmodel.CodeSetupLinkInvalid)

// SetupLink is a single-use link that creates the owner account, shown this
// once; only its hash is stored.
type SetupLink struct {
	URL       string    `json:"url"`
	ExpiresAt time.Time `json:"expires_at"`
}
