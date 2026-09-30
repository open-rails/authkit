package iam

import "time"

// EventKind names a committed change delivered to Deps.OnEvent. Hosts ignore
// kinds they do not know: later versions add kinds.
type EventKind string

const (
	// EventUserRegistered: an account was created (sign-up, sign-in that
	// creates an account, CreateUser, EnsureUserRole, a bootstrap manifest).
	// ImportUsers records no events.
	EventUserRegistered EventKind = "user.registered"
	// EventUserEmailChanged, EventUserPhoneChanged, EventUserUsernameChanged:
	// Previous and Current are the old and new value ("" when none).
	EventUserEmailChanged    EventKind = "user.email_changed"
	EventUserPhoneChanged    EventKind = "user.phone_changed"
	EventUserUsernameChanged EventKind = "user.username_changed"
	// EventUserBanned carries Reason and Until. EventUserUnbanned: a ban in
	// force was lifted; a temporary ban running out records nothing.
	EventUserBanned   EventKind = "user.banned"
	EventUserUnbanned EventKind = "user.unbanned"
	// EventUserDeleted starts the recovery window, EventUserRestored ends it
	// early and EventUserPurged follows the removal of the account row.
	EventUserDeleted  EventKind = "user.deleted"
	EventUserRestored EventKind = "user.restored"
	EventUserPurged   EventKind = "user.purged"
	// EventUserSessionsRevoked: every session and device key of the account
	// was revoked at once (Client.RevokeAccountSessions, DELETE
	// /admin/users/{user_id}/sessions); the actor says whose call it was.
	EventUserSessionsRevoked EventKind = "user.sessions_revoked"
	// Role events carry GroupID, Persona (RootPersona for root roles), the
	// subject (UserID or ApplicationID) and the role as Previous → Current.
	EventRoleGranted EventKind = "role.granted"
	EventRoleChanged EventKind = "role.changed"
	EventRoleRevoked EventKind = "role.revoked"
	// Group events carry GroupID and Persona. A purge records no role events
	// for the assignments it removes.
	EventGroupCreated EventKind = "group.created"
	EventGroupDeleted EventKind = "group.deleted"
	EventGroupPurged  EventKind = "group.purged"
)

// Event is one committed account or group change. It is recorded in the
// transaction that makes the change, so a refused or rolled-back change
// records nothing, and delivered after commit, at least once. It names what
// changed and never carries a credential, hash, token or code.
type Event struct {
	// ID is the same on every delivery: the host's idempotency key.
	ID         string    `json:"id"`
	Kind       EventKind `json:"kind"`
	OccurredAt time.Time `json:"occurred_at"`
	// ActorKind and ActorID name who made the change (ActorID is empty for
	// the system). Both are empty for a change AuthKit made on its own: the
	// end of a recovery window, or a role retired with its grantor's cover.
	ActorKind ActorKind `json:"actor_kind"`
	ActorID   string    `json:"actor_id"`
	// UserID is the account of a user event and the user subject of a role
	// event.
	UserID string `json:"user_id"`
	// GroupID and Persona name the group of a group or role event.
	GroupID string  `json:"group_id"`
	Persona Persona `json:"persona"`
	// ApplicationID is the remote-application subject of a role event.
	ApplicationID string `json:"application_id"`
	// Previous and Current are the changed value before and after: the
	// email, phone or username, or the role (`channel:moderator`); "" when
	// none.
	Previous string `json:"previous"`
	Current  string `json:"current"`
	// Reason and Until describe a ban; Until is nil for an indefinite one.
	Reason string     `json:"reason"`
	Until  *time.Time `json:"until"`
}
