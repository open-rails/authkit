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
//   - Email() authkit.EmailSender, SMS() authkit.SMSSender: the senders.
//   - SetEmailHealth(err), SetSMSHealth(err): what the senders' CheckHealth
//     returns (nil, the default, is healthy), so a test can take a channel
//     down and bring it back.
//
// For example, out.Last(t, iam.MessageVerification, email).Code.
type Outbox = testoutbox.Outbox

// Message is one captured email or SMS: Channel ("email" or "sms"), Kind, To,
// Language and what it carries (Code, Link and the Link's Token, the
// verification Purpose, a ContactChange or DeviceKey notice).
type Message = testoutbox.Message
