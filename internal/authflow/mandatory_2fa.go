package authflow

import (
	"time"

	"github.com/open-rails/authkit/iam"
)

// MFAContinuationRequiredError identifies the already-validated refresh session
// that needs a first-factor continuation. It never authorizes an arbitrary user.
type MFAContinuationRequiredError struct {
	UserID    string
	SessionID string
	Reason    error
}

func (e *MFAContinuationRequiredError) Error() string { return e.Reason.Error() }

func (e *MFAContinuationRequiredError) Unwrap() error { return e.Reason }

type RemovedMFARoleAssignment struct {
	PermissionGroupID string
	Persona           iam.Persona
	InstanceSlug      string
	Role              iam.Role
	RemovedAt         time.Time
}
