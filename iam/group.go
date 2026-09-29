package iam

import "time"

// Group is one permission group: an instance of a persona (/c/golang), or the
// root group, the whole site.
type Group struct {
	ID          string
	Persona     Persona
	Slug        string // "" for the root group
	DisplayName string
	// DeletedAt is set on a soft-deleted group; only by-id reads return one.
	DeletedAt *time.Time
}

// GroupMember is a subject holding a role in a group.
type GroupMember struct {
	Subject Subject
	Role    Role
}

// Membership is a group a subject holds a role in.
type Membership struct {
	Group Group
	Role  Role
}

// NewGroup describes a group to create.
type NewGroup struct {
	Persona     Persona
	Slug        string
	DisplayName string
	// Owner is seeded with the owner role. A user creating a group always
	// becomes its owner and leaves this nil; an operator may name any subject,
	// or none.
	Owner *Subject
}

// GroupUpdate changes a group's own identity; nil fields are unchanged.
type GroupUpdate struct {
	Slug        *string
	DisplayName *string
}

// PurgeGroupOptions controls a permanent group delete. By default the deleted
// group's slug stays reserved forever, so published references can never be
// claimed by someone else. ReleaseSlug frees it; that is safe only for a name
// nothing ever referenced.
type PurgeGroupOptions struct {
	ReleaseSlug bool
}

// GroupQuery lists the groups of a persona ("" = every persona but root),
// ordered by slug. Search matches a substring of the slug or display name.
type GroupQuery struct {
	Persona        Persona
	Search         string
	IncludeDeleted bool
	Page           PageRequest
}

// MemberQuery filters a group's members; empty filters match everything.
type MemberQuery struct {
	Kinds []SubjectKind
	Roles []Role
	Page  PageRequest
}

// CustomRole is a role a group defines at run time, composed from its
// persona's catalog. Whether holding it needs MFA follows from its permissions.
type CustomRole struct {
	Name        Role
	Permissions []string
}
