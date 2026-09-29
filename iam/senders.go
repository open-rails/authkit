package iam

import (
	"errors"
	"strings"
	"time"
)

// Payloads AuthKit hands the host's email and SMS senders.

// VerificationMessage is the payload AuthKit hands a sender: a code, a link, or
// both. Purpose lets senders vary copy without adding new methods.
type VerificationMessage struct {
	// Fixed-length numeric code for manual entry (optional).
	Code string
	// AuthKit-built scanner-safe verification link (optional).
	LinkURL string
	// Purpose lets senders vary copy without adding new sender methods.
	Purpose string
}

func (m VerificationMessage) Validate() error {
	if strings.TrimSpace(m.Code) == "" && strings.TrimSpace(m.LinkURL) == "" {
		return errors.New("verification message must contain at least one of code or link URL")
	}
	return nil
}

// ContactChange is delivered to the PREVIOUS address after a recovery
// identifier (email or phone) was replaced, so a hijacked change is visible to
// the account's real owner.
type ContactChange struct {
	// Field is "email" or "phone".
	Field string
	// NewValue is the replacement address as stored.
	NewValue string
}

// DeviceKeyNotice describes a native-client device key just enrolled on an
// EXISTING account, so a key added through a compromised mailbox is visible to
// the account's real owner.
type DeviceKeyNotice struct {
	Label     string
	CreatedAt time.Time
}
