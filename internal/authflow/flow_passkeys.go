package authflow

import (
	"time"
)

type Passkey struct {
	ID                      string     `json:"id"`
	UserID                  string     `json:"user_id,omitempty"`
	Label                   *string    `json:"label,omitempty"`
	Transports              []string   `json:"transports,omitempty"`
	AuthenticatorAttachment string     `json:"authenticator_attachment,omitempty"`
	BackupEligible          bool       `json:"backup_eligible"`
	BackupState             bool       `json:"backup_state"`
	CreatedAt               time.Time  `json:"created_at"`
	LastUsedAt              *time.Time `json:"last_used_at,omitempty"`
}
