package iam

import "time"

// Passkey is a WebAuthn credential an account signs in with.
type Passkey struct {
	ID                      string     `json:"id"`
	Label                   *string    `json:"label"`
	Transports              []string   `json:"transports"`
	AuthenticatorAttachment *string    `json:"authenticator_attachment"`
	BackupEligible          bool       `json:"backup_eligible"`
	BackupState             bool       `json:"backup_state"`
	CreatedAt               time.Time  `json:"created_at"`
	LastUsedAt              *time.Time `json:"last_used_at"`
}
