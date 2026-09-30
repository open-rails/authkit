# Keys

AuthKit signs tokens with asymmetric keys and publishes their public halves at `/.well-known/jwks.json`. This page covers where the keys live and how to rotate them without a restart.

## The key directory

`KeysConfig.Path` (default `/vault/auth`) holds two files. Keep both readable only by your server.

`keys.json` holds the signing keys:

```json
{
  "active_key_id": "key-2026-06",
  "active_private_key_pem": "-----BEGIN PRIVATE KEY-----\n…",
  "public_keys": {
    "key-2026-03": "-----BEGIN PUBLIC KEY-----\n…"
  }
}
```

- The active key signs every new token, and its `kid` goes in the token header. RSA (2048–8192 bits) signs with RS256, P-256/384/521 with ES256/384/512, and Ed25519 with EdDSA.
- `public_keys` are verify-only keys that JWKS keeps publishing, so tokens signed before a rotation keep verifying.
- With no `keys.json`, `New` fails, unless `KeysConfig.VerifyOnly` is set (no signing) or `AllowEphemeralDevKeys` (development only: AuthKit generates a key, and writes it to `keys.json` when `Path` is set).

`totp.key` is the AES key (16, 24 or 32 bytes; hex, base64 or raw) that encrypts authenticator-app secrets; `TwoFactorConfig.TOTPSecretKey` overrides it. It can't be rotated: replacing it breaks every enrolled authenticator app, so back it up. Without it, authenticator apps can't be enrolled.

To keep the private key out of the process entirely, set `Deps.KeySource` to your own `keys.Source`: an HSM, KMS or Vault key implements `keys.Signer`. A fixed source can't rotate without a restart.

## How rotation works

- **The issuer.** AuthKit reads `keys.json` through `keys.Watch`, which checks the file every 10 seconds and swaps in a changed one. A malformed or unreadable file is logged and ignored; the last good keys stay. Minting and JWKS read the current keys on every call.
- **Verifiers.** A verifier that meets an unknown `kid` refetches the issuer's JWKS once, rate-limited, so other services pick up a new key when its first token arrives. This applies to issuers registered with a `JWKSURI`. Static `IssuerOptions.Keys` never refresh; call `AddIssuer` again with the new keys.
- **Delivery.** `keys.json` must be re-rendered in place while the server runs: a Vault Agent sidecar, or a Kubernetes Secret volume (which syncs within about a minute). An init container that renders the file once defeats hot reload.

Across replicas, a new key reaches each one within 10 seconds. In that window, a replica that hasn't reloaded yet rejects tokens signed with the new key. Clients retry, and the next poll closes the gap.

## Routine rotation

1. Generate a key pair with a new `kid`.
2. In the secret behind `keys.json`, make the new key active and move the old key's public half into `public_keys`.
3. Save. Within 10 seconds every replica signs with the new key, and tokens signed with the old one keep verifying.
4. Once every old token has expired (the access-token lifetime, 15 minutes by default; a day is a safe margin), remove the old key from `public_keys`.

## Emergency rotation

If a key may be compromised, do step 2 without keeping the old public key. Within 10 seconds AuthKit stops accepting tokens signed with it, and other verifiers stop when they next refetch; lower their `IssuerOptions.CacheTTL` to shorten that. Users with those tokens sign in again, or refresh: refresh tokens are opaque and not signed.
