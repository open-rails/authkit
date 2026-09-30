package httpapi

import "github.com/open-rails/authkit/internal/rbac"

// groupsBackend is the compiled role schema the group routes read.
type groupsBackend interface {
	PermissionGroupSchema() *rbac.Schema
}
