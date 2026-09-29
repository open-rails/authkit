package authflow

import (
	"time"
)

// DeviceKeySecondFactorRequired is returned by FinishDeviceKeyEnrollment when
// the email code and key proof are valid but the account has a usable second
// factor that was not presented (#293). The ceremony stays live for a retry
// carrying the code; for SMS/email factors the code has just been sent.
type DeviceKeySecondFactorRequired struct{ Method string }

func (e *DeviceKeySecondFactorRequired) Error() string {
	return "device key enrollment requires a second factor"
}

// DeviceKey is the public projection of one native-client credential.
type DeviceKey struct {
	ID         string     `json:"id"`
	Label      string     `json:"label,omitempty"`
	CreatedAt  time.Time  `json:"created_at"`
	LastUsedAt *time.Time `json:"last_used_at,omitempty"`
	RevokedAt  *time.Time `json:"revoked_at,omitempty"`
}

type DeviceKeyChallenge struct {
	ID        string
	Challenge string
	ExpiresAt time.Time
}

type DeviceKeyAuthResult struct {
	AccessToken string
	ExpiresAt   time.Time
	DeviceKey   DeviceKey
}
