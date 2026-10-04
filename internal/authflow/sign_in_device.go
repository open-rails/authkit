package authflow

import "context"

// SignInDevice is where a sign-in comes from, for Config.SignIn's limits.
// The HTTP layer derives it from the request; the engine sees only hashes.
type SignInDevice struct {
	// ID is "cookie:<hash>" for a browser's device cookie, else
	// "ip:<address>" (an IPv6 /64). Empty: unknown, and not limited.
	ID string `json:"id,omitempty"`
	// Issued is the device cookie this response sets ("cookie:<hash>")
	// beside an ip ID: the browser presents it next time.
	Issued string `json:"issued,omitempty"`
}

// ByAddress reports whether the device is known only by its client address.
func (d SignInDevice) ByAddress() bool { return len(d.ID) > 3 && d.ID[:3] == "ip:" }

type signInDeviceKey struct{}

// WithSignInDevice attaches the request's device to ctx.
func WithSignInDevice(ctx context.Context, d SignInDevice) context.Context {
	return context.WithValue(ctx, signInDeviceKey{}, d)
}

// SignInDeviceFrom is the device WithSignInDevice attached, or none.
func SignInDeviceFrom(ctx context.Context) SignInDevice {
	d, _ := ctx.Value(signInDeviceKey{}).(SignInDevice)
	return d
}

// DeviceChallenge is a sign-in from a new device past
// Config.SignIn.NewDevicesPerAccount: a code went to the account's proven
// Channel ("email" or "sms") at Destination, unmasked. Channels are the
// proven channels a resend may choose.
type DeviceChallenge struct {
	Challenge   string
	Channel     string
	Destination string
	Channels    []string
}

// DeviceVerificationInput confirms a new device with its code.
type DeviceVerificationInput struct {
	UserID    string
	Challenge string
	Code      string
	UserAgent string
	IP        string
}
