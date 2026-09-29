package iam

import "time"

// Group is one permission group: an instance of a persona, or the root
// group, the whole site. A group has no name: it only holds roles. The entity
// it guards (a channel, /c/golang) lives in the host app, which stores the
// group's ID.
type Group struct {
	ID        string
	Persona   Persona
	CreatedAt time.Time
	// DeletedAt is set on a soft-deleted group.
	DeletedAt *time.Time
}

// GroupMember is a subject holding a role in a group. User is the account
// of a user member when MemberQuery.WithUsers asked for it.
type GroupMember struct {
	Subject Subject
	Role    Role
	User    *User
}

// Membership is a group a subject holds a role in.
type Membership struct {
	Group Group
	Role  Role
}

// NewGroup describes a group to create. Owner, when set, is seeded with the
// owner role: a live account, or an enabled remote application.
type NewGroup struct {
	Persona Persona
	Owner   *Subject
}

// GroupQuery lists the groups of a persona ("" = every persona but root),
// oldest first.
type GroupQuery struct {
	Persona        Persona
	IncludeDeleted bool
	Page           PageRequest
}

// MemberQuery filters a group's members; empty filters match everything.
// LiveOnly keeps members that can act now: users not deleted, banned or
// reserved, applications enabled in a live group. WithUsers fills
// GroupMember.User, which carries contact details.
type MemberQuery struct {
	Kinds     []SubjectKind
	Roles     []Role
	LiveOnly  bool
	WithUsers bool
	Page      PageRequest
}

// CustomRole is a role a group defines at run time, composed from its
// persona's catalog. Whether holding it needs MFA follows from its permissions.
type CustomRole struct {
	Name        Role
	Permissions []string
}
