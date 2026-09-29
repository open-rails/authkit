package authflow

import (
	"time"
)

// AccountRecoveryConfirmation is an opaque proof, never an access token or
// session. Confirmation restores this deletion generation without signing in.
type AccountRecoveryConfirmation struct {
	Token     string    `json:"token"`
	ExpiresAt time.Time `json:"expires_at"`
	PurgeAt   time.Time `json:"purge_at"`
}
