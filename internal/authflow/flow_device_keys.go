package authflow

import (
	"time"

	"github.com/open-rails/authkit/iam"
)

// DeviceKeySecondFactorRequired is returned by FinishDeviceKeyEnrollment when
// the email code and key proof are valid but the account has a usable second
// factor that was not presented (#293). Method is a factor independent of the
// enrollment mailbox (totp, sms) or backup_code. The ceremony stays live for a
// retry carrying the code; for an SMS factor the code has just been sent.
type DeviceKeySecondFactorRequired struct{ Method string }

func (e *DeviceKeySecondFactorRequired) Error() string {
	return "device key enrollment requires a second factor"
}

// DeviceKey is the public projection of one native-client credential.
type DeviceKeyChallenge struct {
	ID        string
	Challenge string
	ExpiresAt time.Time
}

// DeviceKeyAuthResult is a device key's sign-in: its account, access token
// and key.
type DeviceKeyAuthResult struct {
	UserID      string
	AccessToken string
	ExpiresAt   time.Time
	DeviceKey   iam.DeviceKey
}
