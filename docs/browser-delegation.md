# Browser delegation

A user signed in at an issuer such as Cozy-art can call another platform
straight from the browser. The issuer authenticates its own user and grants
limited authority; the platform authenticates the issuer and applies its own
resource policy. No application proxy is required for platform requests.

AuthKit supports the ES256/P-256 profile of [RFC 9449 DPoP](https://www.rfc-editor.org/rfc/rfc9449.html).
The existing RFC 8705 certificate path remains available for native clients.
There is no new route, database table or migration.

## Issuance

Enable `embedded.Config.Delegated.AllowDPoP` only after the host's
`DelegatedAuthorization` callback handles `ConfirmationJWKThumbprintSHA256`
and a nil `DelegateCertificate`. DPoP is off by default so existing native
authorizers cannot unexpectedly receive a request without a certificate.

The browser sends `POST /api/v1/delegated/token` with its ordinary local user
access token in `Authorization: Bearer <token>`, a `DPoP` proof header and
`{requested_grant, audiences?, ttl_seconds?}` JSON. It omits
`delegate_certificate_der_b64url`; providing both mechanisms is refused.
The authorizer receives the verified user's ID and public key thumbprint.
A key proves possession, never user identity or permission. Only the returned
grant becomes signed authority; audience, TTL and document rules still apply.
Delegated permissions are scope-free, so a grant may carry a permission in an
AuthKit persona namespace (`root:…`, `org:…`) only when the user holds it at the
root group; otherwise the mint answers `403 delegation_refused`. A checker
built on this runtime (`Runtime.Client()` or the engine) re-checks those
permissions on use, so the token loses them when the user does. Permissions in
the host's own vocabulary remain the authorizer's decision.

The response is `{token, expires_at, token_type: "DPoP"}`. The delegated token
carries exactly `cnf: {"jkt": "<SHA-256 public JWK thumbprint>"}`. Certificate
mints retain their existing two-field response and `cnf.x5t#S256` claim.

## Proof profile

Every proof is a compact JWT with exactly these protected header members:

```json
{"typ":"dpop+jwt","alg":"ES256","jwk":{"kty":"EC","crv":"P-256","x":"...","y":"..."}}
```

Export only these four public JWK fields; WebCrypto's `ext` and `key_ops`
metadata are not part of this profile. Private, symmetric and other-curve keys,
extra header members (including `crit`), duplicate JSON members and malformed
signatures are refused. A proof is limited to 4 KiB.

Required claims are `jti`, `htm`, `htu`, `iat` and `ath`:

- `jti` is a fresh random ID for every request (UUIDv4 is suitable), 16–128 bytes.
- `htm` is the exact HTTP method.
- `htu` is the absolute HTTPS URL without query or fragment. Localhost and
  loopback HTTP are accepted for local development. Scheme/host case, default
  ports and an empty path are normalized; escaped paths otherwise compare
  exactly, so `/a%2Fb` remains distinct from `/a/b`.
- `iat` is an integer Unix timestamp within 60 seconds of the server's clock.
- `ath` is unpadded base64url SHA-256 of the exact presented access token.
  Issuance binds it to the parent user token; resource calls bind it to the
  delegated token. This authenticated mint profile requires `ath` on both.

This profile does not require server nonces. Proof replay claims persist for
all remaining accepted timestamp time, rounded up (at most 121 seconds).
Reusing a proof, even concurrently, is refused. Backend failure fails closed
as an operational `internal_error`; it is never converted to an invalid proof
or a non-atomic fallback. AuthKit's mint and `verify.Required`/`RequiredLive` HTTP responses
include `WWW-Authenticate: DPoP error="invalid_dpop_proof", algs="ES256"`
on proof rejection, while preserving its usual JSON error envelope. A replay
store failure returns a server error without an invalid-proof challenge.
Standalone verifier APIs return errors; their hosts own HTTP challenge headers.

## Direct resource requests

The browser sends `Authorization: DPoP <delegated token>` and a fresh `DPoP`
proof signed by the same key, bound to that resource URL, method and token.
Presenting the token under `Bearer`, detaching verification from the request,
or omitting the proof fails. Certificate and JWK confirmations are mutually
exclusive; neither silently downgrades to bearer authentication.

Configure the receiving verifier with `verify.WithDPoP(replay, requestURL)`.
`requestURL` returns the trusted public URL of this request, including any
proxy-stripped path prefix. It must not trust caller-controlled `Host` or
forwarding headers. `replay` implements `dpop.ReplayGuard`: one atomic claim per
fixed-size key with the supplied TTL, shared across all receiving replicas.
An embedding host can use `embedded.Runtime.ClaimDPoPProof`, which claims in
AuthKit's Postgres ephemeral store. A receiver with its own storage can supply the
minimal callback without importing AuthKit's PostgreSQL engine. Live replay
claims must not be evicted to admit more claims; capacity errors fail closed.
A Redis replay store needs a `noeviction` policy.

Authenticate a request once. After `verify.Required` succeeds, downstream
handlers use `verify.ClaimsFromContext` and authorize from those verified claims.
Calling `VerifyRequest` again with the same proof is a replay, even within the
same application; middleware must pass its verified result to the handler.

The issuer defaults to its configured token issuer's origin plus the received
escaped request path. If ingress strips a public prefix, supply
`authhttp.Config.DPoPRequestURL` with the public path. It ignores untrusted
forwarding headers. This configuration affects proof matching, not routing.

CORS policy remains host-owned. Allow the approved browser origin and the
`Authorization`, `DPoP` and `Content-Type` request headers for supported methods;
preflight must not require an access token. Expose `WWW-Authenticate` through
`Access-Control-Expose-Headers` so the browser can inspect challenges. Successful sender proof does not
replace issuer eligibility, audience, stored permission ceilings, signed
document validation, or per-resource authorization.

## Browser lifecycle

Generate a nonextractable WebCrypto P-256 private key for the active signed-in
session. Keep the key and delegated token together; discard them on logout or
account change. A refresh of the parent access token does not change user
identity; renew delegated tokens with the existing key and a proof for the new
parent token. Retry requests with a newly signed proof, never a reused header.

DPoP limits off-device use of a stolen token. It cannot prevent malicious
JavaScript executing inside the browser from asking the live key to sign.
Keep delegated lifetimes and host grants narrow and retain normal XSS defenses.
