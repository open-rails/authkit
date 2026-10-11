package iam

import (
	"time"

	"github.com/open-rails/helpers/auth"
)

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
	// /admin/users/{user_id}/sessions); the subject says whose call it was.
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
	// Group role events carry GroupID, Persona and Role, a custom role of the
	// group, with its grants before and after, space-separated, as Previous
	// and Current. Deleting one records a role.revoked event for each holder
	// first.
	EventGroupRoleCreated EventKind = "group.role_created"
	EventGroupRoleUpdated EventKind = "group.role_updated"
	EventGroupRoleDeleted EventKind = "group.role_deleted"
	// OAuth client events carry GroupID, Persona and ClientID: a group's
	// client registered, changed (metadata, secret, disabled) or deleted.
	EventOAuthClientCreated EventKind = "oauth_client.created"
	EventOAuthClientUpdated EventKind = "oauth_client.updated"
	EventOAuthClientDeleted EventKind = "oauth_client.deleted"
	// EventOAuthConsentRevoked: UserID withdrew consent to ClientID, of
	// GroupID; the client's refresh tokens for the user ended.
	EventOAuthConsentRevoked EventKind = "oauth_consent.revoked"
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
	// Who made the change (docs/identity.md): the account whose authority
	// it used (SubjectKind, SubjectID), who acted (InvokerIssuer, InvokerID)
	// and how it was proven (CredentialKind, CredentialID). Your own code
	// is CredentialKind "system" with no subject. All are empty for a change
	// AuthKit made on its own: the end of a recovery window, or a role
	// retired with its grantor's cover.
	SubjectKind    auth.SubjectKind    `json:"subject_kind"`
	SubjectID      string              `json:"subject_id"`
	InvokerIssuer  string              `json:"invoker_issuer"`
	InvokerID      string              `json:"invoker_id"`
	CredentialKind auth.CredentialKind `json:"credential_kind"`
	CredentialID   string              `json:"credential_id"`
	// UserID is the account of a user event and the user subject of a role
	// event.
	UserID string `json:"user_id"`
	// GroupID and Persona name the group of a group or role event.
	GroupID string  `json:"group_id"`
	Persona Persona `json:"persona"`
	// ApplicationID is the remote-application subject of a role event.
	ApplicationID string `json:"application_id"`
	// Role is the custom role of a group role event.
	Role Role `json:"role"`
	// ClientID is the OAuth client of a client or consent event.
	ClientID string `json:"client_id"`
	// Previous and Current are the changed value before and after: the
	// email, phone or username, the role (`channel:moderator`), or a group
	// role's grants; "" when none.
	Previous string `json:"previous"`
	Current  string `json:"current"`
	// Reason and Until describe a ban; Until is nil for an indefinite one.
	Reason string     `json:"reason"`
	Until  *time.Time `json:"until"`
}
