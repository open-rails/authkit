package authtest

import "github.com/open-rails/authkit/internal/testoutbox"

// Outbox captures every email and SMS AuthKit sends, in order, so a test can
// complete sign-up, verification, reset and sign-in flows. New wires one; for
// a Client built another way, pass Email() and SMS() as Deps.Email and
// Deps.SMS. Its methods:
//
//   - Last(t, kind, to) Message: the newest message of kind to that address
//     or number ("" = anyone); the test fails when there is none.
//   - Messages(kind, to) []Message: all of them, oldest first ("" = any).
//   - Email(), SMS(): the senders.
//
// For example, out.Last(t, authtest.Verification, email).Code.
type Outbox = testoutbox.Outbox

// Message is one captured email or SMS: Channel ("email" or "sms"), Kind, To,
// and what it carries (Code, Link and the Link's Token, the verification
// Purpose, a ContactChange or DeviceKey notice).
type Message = testoutbox.Message

// Kind names what a Message is for.
type Kind = testoutbox.Kind

// Message kinds.
const (
	// Verification proves a contact: registration, a contact change, a
	// passwordless sign-in, a device-key enrollment or a factor setup
	// (Message.Purpose says which).
	Verification = testoutbox.Verification
	// LoginCode is a second-factor sign-in code.
	LoginCode = testoutbox.LoginCode
	// PasswordReset carries a reset link.
	PasswordReset     = testoutbox.PasswordReset
	AccountInvite     = testoutbox.AccountInvite
	Welcome           = testoutbox.Welcome
	ContactChanged    = testoutbox.ContactChanged
	DeviceKeyEnrolled = testoutbox.DeviceKeyEnrolled
	MFAReset          = testoutbox.MFAReset
)
