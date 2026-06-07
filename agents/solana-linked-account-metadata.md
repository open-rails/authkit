# Solana linked-account metadata contract

AuthKit owns Solana wallet identity metadata for SIWS-linked accounts. Host apps
should not resolve Solana Name Service names directly or attach their own
wallet-display metadata to user profiles.

## Shape

AuthKit-linked Solana accounts should expose this normalized shape in profile or
linked-identity APIs:

```json
{
  "provider": "solana",
  "issuer": "solana:mainnet",
  "address": "H8L3...",
  "verified": true,
  "verified_at": "2026-06-07T00:00:00Z",
  "primary_sns_name": "example.sol",
  "sns_resolution_status": "resolved",
  "sns_resolved_at": "2026-06-07T00:00:00Z",
  "sns_stale": false,
  "sns_error": null
}
```

Field semantics:

- `provider`: always `solana` for Solana wallet links.
- `issuer`: AuthKit issuer/network key such as `solana:mainnet`,
  `solana:devnet`, or `solana:testnet`.
- `address`: base58 Solana wallet address.
- `verified`: true only after SIWS signature verification succeeds for this
  address.
- `verified_at`: timestamp of the successful SIWS link/login verification, when
  available.
- `primary_sns_name`: nullable primary `.sol` name resolved for `address`.
- `sns_resolution_status`: one of `disabled`, `pending`, `resolved`,
  `not_found`, `error`, or `stale`.
- `sns_resolved_at`: last successful or terminal lookup timestamp.
- `sns_stale`: true when cached SNS data is past the configured fresh TTL.
- `sns_error`: nullable stable error code for observability, never raw provider
  payload.

## Behavior

AuthKit should resolve SNS on wallet link and refresh cached names
asynchronously when stale. SNS lookup failures must not block login, account
rendering, wallet linking, or wallet unlinking. Consumers should display
`primary_sns_name` when present and fall back to the shortened wallet address
otherwise.

If ownership changes or the resolver later reports no primary name, AuthKit
should clear `primary_sns_name`, update `sns_resolution_status`, and keep the
verified wallet link intact.
