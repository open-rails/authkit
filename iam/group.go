package iam

import (
	"time"

	"github.com/open-rails/authkit/internal/errmodel"
)

// ErrGroupConflict refuses to create a group whose id is taken by a deleted
// group or a group of another persona.
var ErrGroupConflict Error = errmodel.E(errmodel.CodeGroupConflict)

// Group is one permission group: an instance of a persona, or the root
// group, the whole site. A group has no name: it only holds roles. The entity
// it guards (a channel, /c/golang) lives in the host app, which stores the
// group's ID.
type Group struct {
	ID        string    `json:"id"`
	Persona   Persona   `json:"persona"`
	CreatedAt time.Time `json:"created_at"`
	// DeletedAt is set on a soft-deleted group.
	DeletedAt *time.Time `json:"deleted_at"`
}

// GroupMember is a subject holding a role in a group. User is the account
// of a user member when MemberQuery.WithUsers asked for it.
type GroupMember struct {
	Subject Subject     `json:"subject"`
	Role    Role        `json:"role"`
	User    *PublicUser `json:"user"`
}

// Membership is a group a subject holds a role in.
type Membership struct {
	Group Group `json:"group"`
	Role  Role  `json:"role"`
}

// NewGroup describes a group to create. ID, when set, is the group's id: any
// uuid the host keys the group by, such as its own row's id or a user's id.
// Creating an id that exists returns that group unchanged when it is a live
// group of Persona, and is iam.ErrGroupConflict otherwise. Owner, when set, is
// seeded with the owner role of a new group: a live account, or an enabled
// remote application.
type NewGroup struct {
	ID      string
	Persona Persona
	Owner   *Subject
}

// GroupQuery lists the groups of a persona (zero = every persona but root),
// oldest first. Ownerless keeps only live groups that no owner counts for
// under the last-owner rule: created without one, or left without one by the
// credential sweep at boot. An owner whose required MFA enrollment is pending
// does not count.
type GroupQuery struct {
	Persona        Persona
	IncludeDeleted bool
	Ownerless      bool
	Page           PageRequest
}

// MemberQuery filters a group's members; empty filters match everything.
// LiveOnly keeps members that can act now: users not deleted or banned,
// applications enabled in a live group. WithUsers fills
// GroupMember.User, which carries contact details.
type MemberQuery struct {
	Kinds     []SubjectKind
	Roles     []Role
	LiveOnly  bool
	WithUsers bool
	Page      PageRequest
}
