# Contact ownership

Anyone can register `victim@example.com`. Until someone proves control of an
account's address, AuthKit treats whoever created its credentials as a
stranger to that address (ak#393).

## Rules

- **Never verified without proof.** Registration stores the address unverified
  under every policy. `none` only means verification is not required to use the
  account; `optional` also sends a code at registration. Proofs are: a
  registration, verification or contact-change code/link, a completed password
  reset, a passwordless code/link, device-key enrollment, and an identity
  provider trusted to verify addresses.
- **No new login methods while unproven.** An account with an address but none
  proven cannot link an identity provider or Solana wallet, register a passkey,
  or enroll a 2FA factor. The first factor of a deployment that mandates 2FA is
  the exception; the first proof retires it. These requests answer
  `403 verification_required` with `metadata` `{identifier, channel,
  reason: "contact_unproven"}`. Send a code with `POST /verify/request` and
  confirm it at `POST /verify/confirm`. Accounts with no email or phone are
  unaffected.
- **The first proof retires everything before it.** In the proof's transaction,
  AuthKit deletes provider links (including wallets), passkeys, device keys,
  2FA factors and backup codes. It revokes API keys the account created and
  every refresh session on every account issuer. The session presenting the
  proof is the only exception, when there is one.
- **The password survives only if the prover holds it.** A proof presented by a
  live session of the account that signed in with the password keeps the
  password, because the registrant is verifying their own address. A proof from
  another device, an email/SMS login code or device-key enrollment deletes the
  password. A reset replaces it. Proving on another device signs the prover in;
  they set a new password if they want one.
- **Provider email trust.** A provider's `email_verified` counts only when
  `Provider.TrustsEmailVerification()` is true. Google, Apple, GitHub and
  Discord are trusted by default. Generic `authprovider.OIDC`/`OAuth2`
  providers are untrusted unless configured with
  `authprovider.WithTrustedEmailVerification(true)`. An untrusted provider's
  address is ignored: it never creates a verified account or matches an
  existing one.
