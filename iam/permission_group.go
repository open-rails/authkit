package iam

import "errors"

// ErrUnknownPermission reports a permission no persona catalog registers. It
// is a programming error, so it has no wire code.
var ErrUnknownPermission = errors.New("iam: unknown permission")

// validSegment reports whether s is one permission segment (a persona,
// resource, action or role name): [a-z][a-z0-9-]*.
func validSegment(s string) bool {
	if s == "" || s[0] < 'a' || s[0] > 'z' {
		return false
	}
	for i := 1; i < len(s); i++ {
		if c := s[i]; (c < 'a' || c > 'z') && (c < '0' || c > '9') && c != '-' {
			return false
		}
	}
	return true
}
