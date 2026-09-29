package iam

import (
	"errors"
	"fmt"
	"regexp"
	"strings"
)

// ErrUnknownPermission reports a permission no persona catalog registers. It
// is a programming error, so it has no wire code.
var ErrUnknownPermission = errors.New("iam: unknown permission")

// segmentRe matches ONE lowercase permission segment (persona, resource, or
// action): a letter followed by letters/digits/hyphens.
var segmentRe = regexp.MustCompile(`^[a-z][a-z0-9-]*$`)

// ValidPermissionSegment reports whether s is one permission segment (a
// persona, resource, action or custom role name).
func ValidPermissionSegment(s string) bool { return segmentRe.MatchString(s) }

// ValidateGroupInstanceSlug checks the slug of a by-slug reference.
func ValidateGroupInstanceSlug(g GroupRef) error {
	if g.IsRoot() || g.ID() != "" {
		return nil
	}
	if !ValidSlug(g.Slug()) {
		return fmt.Errorf("resource slug %q must be lowercase URL-safe", g.Slug())
	}
	return nil
}

// ValidatePermission checks a CONCRETE catalog permission: EXACTLY three
// lowercase segments `<persona>:<resource>:<action>` (e.g. `merchant:catalog:update`,
// `root:users:ban`). Two-part (`repo:update`) and four-part perms are rejected.
func ValidatePermission(p string) error {
	segs := strings.Split(p, ":")
	if len(segs) != 3 {
		return fmt.Errorf("permission %q must be exactly three segments <persona>:<resource>:<action>", p)
	}
	for _, s := range segs {
		if !segmentRe.MatchString(s) {
			return fmt.Errorf("permission %q: segment %q must match [a-z][a-z0-9-]*", p, s)
		}
	}
	return nil
}

// ValidateGrantPattern checks a GRANT token (what a role holds). Grants may be
// concrete perms OR namespace-anchored globs, but NEVER a bare `*`:
//
//	<persona>:<resource>:<action>   a concrete perm
//	<persona>:<resource>:*          all actions on a resource
//	<persona>:*                     the whole persona namespace (the owner grant)
//
// The persona segment is always a literal — a bare `*` or `*`-persona is
// rejected, so a `merchant:*` grant never names a `root:` or `customer:`
// permission. Mirrors Perm.Matches but is STRICTER: it forbids mid-glob forms
// like `persona:*:action`.
func ValidateGrantPattern(g string) error {
	if g == "" {
		return fmt.Errorf("empty grant")
	}
	segs := strings.Split(g, ":")
	if !segmentRe.MatchString(segs[0]) {
		return fmt.Errorf("grant %q: persona segment must be a literal lowercase name (no bare *)", g)
	}
	switch len(segs) {
	case 2:
		if segs[1] != PermWildcard {
			return fmt.Errorf("grant %q: a two-segment grant must be <persona>:*", g)
		}
		return nil
	case 3:
		if !segmentRe.MatchString(segs[1]) {
			return fmt.Errorf("grant %q: resource segment must match [a-z][a-z0-9-]*", g)
		}
		if segs[2] != PermWildcard && !segmentRe.MatchString(segs[2]) {
			return fmt.Errorf("grant %q: action segment must be a name or *", g)
		}
		return nil
	default:
		return fmt.Errorf("grant %q: must be <persona>:* , <persona>:<resource>:* , or <persona>:<resource>:<action>", g)
	}
}
