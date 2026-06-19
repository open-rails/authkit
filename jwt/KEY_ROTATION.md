# JWT signing-key rotation

How to rotate AuthKit's RS256 signing keys **without a process restart**.

Applies to file-delivered keys (`/vault/auth/keys.json`). Env-delivered keys
(`ACTIVE_KEY_ID` / `ACTIVE_PRIVATE_KEY_PEM` / `PUBLIC_KEYS`) cannot hot-rotate —
env is immutable in a running process, so an env-based deploy must restart to
pick up a new key. Use file delivery in production.

## How it works

`keys.json` is a single envelope:

```json
{
  "active_key_id":         "key-2026-06",
  "active_private_key_pem": "<the key that SIGNS new tokens>",
  "public_keys": {
    "key-2026-03": "<retired key — verify-only, still in JWKS>"
  }
}
```

- `active_*` is the signer. Every issued token carries its `kid` in the header.
- `public_keys` is a map of extra **verify-only** keys served from JWKS. This map
  is the entire rotation mechanism: it lets old and new keys overlap so in-flight
  tokens keep verifying across a rotation.

Two pieces make rotation reboot-free:

1. **Issuer side — `ReloadableKeySource`** (`jwt/keys.go`). When keys are loaded
   from a file, AuthKit serves them through a source that re-stats `keys.json`
   every `DefaultKeyReloadInterval` (10s) and atomically swaps in the new keystore
   on change. A malformed/unreadable file is rejected and the last-good keystore
   is kept (a bad render never bricks signing). So the issuer's own
   `/.well-known/jwks.json` reflects a rotation within ~10s, no restart.
2. **Verifier side — unknown-kid refetch** (`http/verifier.go`). Any verifier
   (federated consumer, or AuthKit verifying another issuer) that sees a token
   signed by a `kid` it doesn't have force-refetches the issuer's JWKS once
   (rate-limited, single-flight), then accepts if present / rejects if absent.
   So external verifiers pick up the rotated key on demand.

**Accepted tradeoff:** across a replica fleet there is a few-second window after a
rotation where replica A (already reloaded) signs with the new key and replica B
(not yet reloaded) rejects it. Clients retry/re-auth; it self-heals on B's next
poll (≤10s). This is acceptable and intentional — we do not add a per-request
backstop to close it to zero.

## Infra prerequisite

`keys.json` must be delivered by a **long-running Vault Agent sidecar** (or
equivalent) that re-renders the file in place when the secret changes. An
**init-container-only** render writes the file once at boot and never updates it —
that defeats hot-reload and forces a restart. Confirm the agent is a sidecar, not
`agent-pre-populate-only`. (A K8s Secret volume synced by External Secrets also
works, with the kubelet's ~60–90s sync latency instead of ~seconds.)

## Routine rotation

1. Generate a new keypair (new `kid`).
2. Update the Vault secret backing `keys.json`:
   - set `active_key_id` / `active_private_key_pem` to the **new** key;
   - move the **previous** key's *public* PEM into `public_keys` (keep it for one
     access-token TTL — currently 15 min — so in-flight tokens still verify).
3. Save. Vault Agent re-renders the file; every replica's poller swaps it in
   within ~10s. New tokens sign with the new key; old tokens verify against the
   retained public key; external verifiers refetch on the new `kid`.
4. **Cleanup (next day):** remove the old entry from `public_keys` and save. By
   then every token signed by the old key has expired.

No restart at any step.

## Emergency rotation (suspected key compromise)

Same as routine, but in step 2 **do not** retain the old public key — drop it
from `public_keys` immediately. After the ~10s pickup, every token signed by the
compromised key fails verification everywhere (and external verifiers drop it on
their next refetch). Cost: all in-flight tokens signed by the old key die and
users re-authenticate — a small blast radius given the 15-min access-token TTL.

If you need to shrink the external-verifier window further, also lower their JWKS
cache TTL; the issuer side is already immediate.

## Local testing

The dev/compose host mount (`./.secrets/authkit` → `/vault/auth`) makes this
testable by hand: edit `keys.json` and watch the poller reload it. See
`jwt/keys_reload_test.go` for the reload/keep-old-on-error/poller coverage.
