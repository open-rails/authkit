package ident

import (
	"fmt"
	"net/url"
	"strings"

	"github.com/open-rails/authkit/iam"
)

// ValidSegment reports whether s is one permission segment (a persona,
// resource, action or role name): [a-z][a-z0-9-]*.
func ValidSegment(s string) bool {
	var p iam.Persona
	return s != "" && p.UnmarshalText([]byte(s)) == nil
}

// ValidatePermission checks a concrete catalog permission: exactly three
// segments `<persona>:<resource>:<action>` (`merchant:catalog:update`).
func ValidatePermission(p string) error {
	segs := strings.Split(p, ":")
	if len(segs) != 3 {
		return fmt.Errorf("permission %q must be exactly three segments <persona>:<resource>:<action>", p)
	}
	for _, s := range segs {
		if !ValidSegment(s) {
			return fmt.Errorf("permission %q: segment %q must match [a-z][a-z0-9-]*", p, s)
		}
	}
	return nil
}

// ValidateGrantPattern checks what a role holds: a concrete permission or a
// namespace-anchored glob, never a bare `*`:
//
//	<persona>:<resource>:<action>   a concrete permission
//	<persona>:<resource>:*          every action on a resource
//	<persona>:*                     the whole persona namespace (the owner)
//
// It is stricter than iam.Perm.Matches: it refuses mid-glob forms such as
// `persona:*:action`.
func ValidateGrantPattern(g string) error {
	if g == "" {
		return fmt.Errorf("empty grant")
	}
	segs := strings.Split(g, ":")
	if !ValidSegment(segs[0]) {
		return fmt.Errorf("grant %q: persona segment must be a literal lowercase name (no bare *)", g)
	}
	switch len(segs) {
	case 2:
		if segs[1] != iam.PermWildcard {
			return fmt.Errorf("grant %q: a two-segment grant must be <persona>:*", g)
		}
		return nil
	case 3:
		if !ValidSegment(segs[1]) {
			return fmt.Errorf("grant %q: resource segment must match [a-z][a-z0-9-]*", g)
		}
		if segs[2] != iam.PermWildcard && !ValidSegment(segs[2]) {
			return fmt.Errorf("grant %q: action segment must be a name or *", g)
		}
		return nil
	default:
		return fmt.Errorf("grant %q: must be <persona>:* , <persona>:<resource>:* , or <persona>:<resource>:<action>", g)
	}
}

// MaxIssuerLen bounds a remote-application issuer.
const MaxIssuerLen = 512

// ValidIssuer reports whether iss has the shape every registered
// remote-application issuer has: an absolute http(s) URL with a host, at most
// MaxIssuerLen bytes, no whitespace or control characters. Registration
// enforces it, and the verifier applies it to a token's self-asserted iss
// before any store lookup.
func ValidIssuer(iss string) bool {
	if iss == "" || len(iss) > MaxIssuerLen {
		return false
	}
	for _, r := range iss {
		if r <= ' ' || r == 0x7f {
			return false
		}
	}
	u, err := url.Parse(iss)
	if err != nil {
		return false
	}
	return (u.Scheme == "http" || u.Scheme == "https") && u.Host != ""
}
