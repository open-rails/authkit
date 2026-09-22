package verify

import (
	"strings"

	authkit "github.com/open-rails/authkit"
	"github.com/open-rails/authkit/internal/rootsnapshot"
)

type verifiedRootSnapshot struct {
	value  *rootsnapshot.Value
	userID string
}

// RootPermissionSnapshot evaluates token-time authority for a concrete root
// permission without I/O. complete=false means unavailable: callers must use
// their live authorization path, not interpret it as an authoritative denial.
// A complete negative can skip a live lookup. Sensitive positive decisions
// should still check current permission and account liveness. New grants only
// appear after refresh. This does not change Can, Allow, or other group scopes.
// Only cryptographically verified local native-user claims carry a snapshot.
func (c Claims) RootPermissionSnapshot(permission authkit.Perm) (allowed, complete bool) {
	snapshot := c.rootPermissions
	if snapshot == nil || snapshot.userID != c.UserID || c.UserID == "" || c.Subject != "" || c.DelegatedSubject != "" || c.TokenType != "" || !strings.EqualFold(c.TokenTyp, AccessTokenType) || c.TwoFAEnrollment || snapshot.value.Issuer != c.Issuer || !rootsnapshot.Concrete(string(permission)) {
		return false, false
	}
	for _, grant := range snapshot.value.Grants {
		if permission.Matches(authkit.Perm(grant)) {
			return true, true
		}
	}
	return false, true
}
