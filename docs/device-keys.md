# Device keys

A device key is a CLI's or machine's credential: an Ed25519 key enrolled
once with a code emailed to the account, then used to sign in for short
access tokens. There is no refresh token; signing a fresh challenge is the
refresh. Hosts opt in with `Config.DeviceKeys.Enabled`, which mounts the
`device_keys` route group ([routes](api-endpoints.md)).

## Protocol

| Step | Request | Answer |
|---|---|---|
| Begin enrollment | `POST {api}/device-keys/enroll/begin` `{email, public_key, label?}` | `202 {enrollment_id, challenge, expires_at}`; a code is emailed |
| Finish enrollment | `POST {api}/device-keys/enroll/finish` `{enrollment_id, code, signature, code_2fa?}` | `200 {token_set, device_key}` |
| Begin login | `POST {api}/device-keys/login/begin` `{device_key_id}` | `202 {challenge_id, challenge, expires_at}` |
| Finish login | `POST {api}/device-keys/login/finish` `{challenge_id, signature}` | `200 {token_set, device_key}` |

Keys, challenges and signatures are unpadded base64url. The key signs
`domain || 0x00 || challenge` over the raw 32-byte challenge, with
`authkit.device-key-enrollment/1` to enroll and `authkit.device-key-login/1`
to sign in, so neither signature replays as the other. A new address creates
the account where registration is open.

An account with a second factor answers the first finish with
`403 step_up_required`, `metadata.method` naming the factor (`totp`, `sms`,
whose code is sent then, or `backup_code`; never the email factor, which reads
the enrollment mailbox). Retry the same finish with `code_2fa`. Only a key
enrolled this way counts as a second factor at login; any other key is refused
(`2fa_required`) where a sign-in needs a second factor, until re-enrolled.

A device-key token lists (`GET {api}/device-keys`) and revokes
(`DELETE {api}/device-keys/{id}`) the account's keys. Only an enrollment
token, which also proves the email, revokes every other key
(`POST {api}/device-keys/revoke-others`); re-enrolling a live key returns it
unchanged with such a token.

## Go client

`github.com/open-rails/authkit/devicekey` speaks this protocol and depends
only on the standard library and `iam`:

```go
c, err := devicekey.NewClient("https://example.com/api/v1", nil)
pub, priv, _ := ed25519.GenerateKey(rand.Reader)
e, err := c.BeginEnrollment(ctx, email, pub, "laptop")
s, err := c.FinishEnrollment(ctx, e, priv, emailedCode, "")
var sf *devicekey.SecondFactorRequired
if errors.As(err, &sf) {
	s, err = c.FinishEnrollment(ctx, e, priv, emailedCode, prompt(sf.Method))
}
// Store s.DeviceKey.ID and priv; later:
s, err = c.Login(ctx, id, priv)
```

Keys are `crypto.Signer`s, so a hardware- or agent-held Ed25519 key works.
`SignEnrollment`, `SignLogin` and `Message` expose the signing for hosts that
drive the routes themselves. Refusals are `iam.Error`s decoded by
`iam.DecodeError`: `invalid_code` (wrong code, or a revoked or foreign key),
`invalid_credentials` (login with an unknown or revoked key: enroll again),
`2fa_required`, `2fa_enrollment_required` (`iam.ErrTwoFAEnrollmentRequired`),
`rate_limited` (`metadata.retry_after_seconds`). A host without device keys
answers `404` with no code.
