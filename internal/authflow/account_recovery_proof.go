package authflow

import (
	"time"
)

// AccountRecoveryConfirmation is an opaque proof, never an access token or
// session. Only POST /account/recovery/confirm takes it: confirmation restores
// this deletion generation and continues the sign-in that earned it.
type AccountRecoveryConfirmation struct {
	Token     string    `json:"token"`
	ExpiresAt time.Time `json:"expires_at"`
	PurgeAt   time.Time `json:"purge_at"`
}
