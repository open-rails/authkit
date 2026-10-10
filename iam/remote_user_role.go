package iam

import "time"

// RemoteUserRole is a role a trusted issuer's user holds in a group: the
// role an email invitation granted, accepted with that verified address
// (Client.AcceptRemoteInvitation). The user's tokens hold its permissions
// there, within their application's role.
type RemoteUserRole struct {
	// RemoteUserID is the user's record in the group's directory.
	RemoteUserID string    `json:"remote_user_id"`
	Issuer       string    `json:"issuer"`
	Subject      string    `json:"subject"`
	Email        string    `json:"email"`
	Role         Role      `json:"role"`
	CreatedAt    time.Time `json:"created_at"`
}
