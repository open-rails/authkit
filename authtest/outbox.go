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
	Verification      = testoutbox.Verification      // proves a contact; Message.Purpose says for what
	LoginCode         = testoutbox.LoginCode         // a second-factor sign-in code
	PasswordReset     = testoutbox.PasswordReset     // a reset link
	AccountInvite     = testoutbox.AccountInvite     // an account registration invitation link
	Welcome           = testoutbox.Welcome           // follows a completed registration
	ContactChanged    = testoutbox.ContactChanged    // to the address or number just replaced
	DeviceKeyEnrolled = testoutbox.DeviceKeyEnrolled // a device key can now sign in
	MFAReset          = testoutbox.MFAReset          // the system removed the second factors
)
