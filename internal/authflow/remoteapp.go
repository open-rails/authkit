package authflow

import "github.com/open-rails/authkit/iam"

// RegisteredApplication is the result of a (re-)registration: the application
// row plus its service-owned org (the permission group the application
// principal owns).
type RegisteredApplication struct {
	Application     iam.RemoteApplication
	OrgPersona      iam.Persona
	OrgInstanceSlug string
	// Created is false for an idempotent re-registration (the boot-time
	// self-heal / rotation-from-root path).
	Created bool
}
