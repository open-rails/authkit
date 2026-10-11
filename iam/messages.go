package iam

import "time"

// MessageKind names what an email or SMS is for. Later versions add kinds: a
// sender ignores or refuses a kind it does not know.
type MessageKind string

const (
	// MessageVerification proves a contact: Code, an optional Link, and
	// Purpose says what for.
	MessageVerification MessageKind = "verification"
	// MessageLoginCode is a second-factor sign-in Code.
	MessageLoginCode MessageKind = "login_code"
	// MessagePasswordReset carries a reset Link.
	MessagePasswordReset MessageKind = "password_reset"
	// MessageInvite invites an address to create an account (email only):
	// Link.
	MessageInvite MessageKind = "invite"
	// MessageWelcome follows a completed registration (email only).
	MessageWelcome MessageKind = "welcome"
	// MessageContactChanged goes to the address or number an account just
	// replaced: ContactChange.
	MessageContactChanged MessageKind = "contact_changed"
	// MessageDeviceKeyEnrolled tells an existing account that a device key can
	// now sign in as it (email only): DeviceKey.
	MessageDeviceKeyEnrolled MessageKind = "device_key_enrolled"
	// MessageNewDeviceCode is the Code a new device enters to sign in once
	// the account has had too many new devices today
	// (Config.SignIn.NewDevicesPerAccount). It tells the owner someone is
	// signing in, and to change the password if it was not them.
	MessageNewDeviceCode MessageKind = "new_device_code"
	// MessageMFAReset tells an account that the system removed its passkeys,
	// second factors and device keys and signed it out everywhere (email only).
	MessageMFAReset MessageKind = "mfa_reset"
)

// VerificationPurpose says what a MessageVerification proves the contact for.
type VerificationPurpose string

const (
	PurposeSignup              VerificationPurpose = "signup"
	PurposeContactVerify       VerificationPurpose = "contact_verify"
	PurposeContactChange       VerificationPurpose = "contact_change"
	PurposePasswordlessLogin   VerificationPurpose = "passwordless_login"
	PurposeTwoFactorSetup      VerificationPurpose = "2fa_setup"
	PurposeDeviceKeyEnrollment VerificationPurpose = "device_key_enrollment"
)

// EmailMessage is one email AuthKit asks Deps.Email to deliver. Fields a kind
// does not use are empty.
type EmailMessage struct {
	Kind MessageKind
	To   string
	// Username is the account's username, "" when it has none.
	Username string
	// Language is a two-letter code: the account's preferred language, else
	// the request's, else the configured default.
	Language      string
	Code          string
	Link          string
	Purpose       VerificationPurpose
	ContactChange *ContactChange
	DeviceKey     *DeviceKeyNotice
}

// SMSMessage is one text message AuthKit asks Deps.SMS to deliver. Fields a
// kind does not use are empty.
type SMSMessage struct {
	Kind MessageKind
	To   string
	// Language is a two-letter code, chosen as for EmailMessage.
	Language      string
	Code          string
	Link          string
	Purpose       VerificationPurpose
	ContactChange *ContactChange
	// UserID is the account the message is for; empty before one exists.
	UserID string
	// Domain is the host a Code is entered on (Frontend.BaseURL's). A body
	// whose last line is "@<Domain> #<Code>" lets browsers autofill the code
	// on that origin only (WICG origin-bound one-time codes); the built-in
	// templates end with it, and OriginBoundLine renders it.
	Domain string
}

// OriginBoundLine is the line a code message ends with, "@<Domain>
// #<Code>", or "" when either is missing.
func (m SMSMessage) OriginBoundLine() string {
	if m.Domain == "" || m.Code == "" {
		return ""
	}
	return "@" + m.Domain + " #" + m.Code
}

// ContactChange is delivered to the PREVIOUS address after a recovery
// identifier (email or phone) was replaced, so a hijacked change is visible to
// the account's real owner.
type ContactChange struct {
	Field ContactField
	// NewValue is the replacement address as stored.
	NewValue string
}

// ContactField names a recovery identifier.
type ContactField string

const (
	ContactEmail ContactField = "email"
	ContactPhone ContactField = "phone"
)

// DeviceKeyNotice describes a native-client device key just enrolled on an
// EXISTING account, so a key added through a compromised mailbox is visible to
// the account's real owner.
type DeviceKeyNotice struct {
	Label     string
	CreatedAt time.Time
}
