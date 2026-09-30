// Package ident builds iam identifiers from strings AuthKit already trusts:
// stored rows, verified token claims, its compiled role schema and its own
// tests. A string that fails the syntax check yields the zero value, which
// matches and grants nothing. Host input goes through the schema instead
// (Client.Persona, Client.Permission, Client.Role).
package ident

import (
	"fmt"

	"github.com/open-rails/authkit/iam"
)

func Persona(s string) iam.Persona {
	var p iam.Persona
	_ = p.UnmarshalText([]byte(s))
	return p
}

func Perm(s string) iam.Perm {
	var p iam.Perm
	_ = p.UnmarshalText([]byte(s))
	return p
}

// Role is persona's role name; the zero Role when either is invalid.
func Role(persona iam.Persona, name string) iam.Role {
	var r iam.Role
	if persona.IsZero() || name == "" {
		return r
	}
	_ = r.UnmarshalText([]byte(persona.String() + ":" + name))
	return r
}

// RoleText reads a role's text form `<persona>:<name>`, as rows store it;
// the zero Role when it is malformed.
func RoleText(s string) iam.Role {
	var r iam.Role
	_ = r.UnmarshalText([]byte(s))
	return r
}

// Perms converts each string with Perm.
func Perms(ss []string) []iam.Perm {
	if ss == nil {
		return nil
	}
	out := make([]iam.Perm, len(ss))
	for i, s := range ss {
		out[i] = Perm(s)
	}
	return out
}

// Strings is each value's String.
func Strings[T fmt.Stringer](vs []T) []string {
	if vs == nil {
		return nil
	}
	out := make([]string, len(vs))
	for i, v := range vs {
		out[i] = v.String()
	}
	return out
}
