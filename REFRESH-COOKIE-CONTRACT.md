# AuthKit — Refresh-Session Cookie Contract (proposal)

**Status:** proposal, not implemented. Owner review required — see §14.
**Consumers:** hentai0 (#234), doujins (#792). One contract, two repos, independent version pins.
**Version posture:** every change below is **additive** (new routes, new optional response
fields, new response header, new config). Under [SEMVER.md](SEMVER.md) that is **MINOR**.
Removing `refresh_token` from `POST /token`'s request/response bodies is a **response-shape
change and therefore MAJOR** — it is explicitly *out of scope here* and deferred to a future
major. This contract makes the cookie the durable credential without breaking the body path.

---

## 1. Threat model — what this fixes, and what it does not

Today the refresh token is readable by script (`localStorage` in hentai0; IndexedDB with a
`localStorage` fallback in doujins). Any XSS exfiltrates a **durable, offline** credential and
replays it from the attacker's machine for the life of the session.

This contract makes the durable credential unreadable by script.

It does **not** stop an XSS payload executing in a live tab from calling the refresh endpoint
with `credentials: 'include'` and minting access tokens ("session riding"). No browser-side
design prevents that. The gain is bounded and real: **theft-and-replay-from-elsewhere is
eliminated; abuse is confined to the window in which attacker script is executing in the
victim's own tab.** Do not describe this as "XSS-proof".

Access tokens remain **JS-readable values in memory**. They must: the HTTP clients build the
`Authorization` header synchronously at send time, and the cross-origin payment iframe receives a
bearer token by `postMessage` — a cookie can never serve that origin (§9.4).

---

## 2. Cookie specification

| Property | Value | Why |
| --- | --- | --- |
| Name | `authkit_rt` | See §2.1 — `__Host-` is **rejected**, deliberately. |
| Value | `<token>.<b64url(HMAC-SHA256(cookieKey, token))>` | §2.2 — closes cookie shadowing. |
| `HttpOnly` | always | The entire point. |
| `Secure` | when derivable from the configured BaseURL/request | Never in plain-HTTP dev, or dev breaks. |
| `SameSite` | `Lax` | **MUST NEVER be `Strict`.** The OIDC state cookie must survive the IdP's cross-site top-level GET back to `/{provider}/callback`; `Strict` drops it and every social login fails `invalid_state`. |
| `Domain` | omitted (host-only) | Three registrable domains, no shared parent. §14.2. |
| `Path` | `/api/v1/session` | §2.1 — keeps the cookie off ordinary API calls. |
| `Max-Age` | session TTL when finite; omitted when the session has no `expires_at` | Mirrors `refresh_sessions.expires_at`. |

### 2.1 Path scoping, and why `__Host-` is rejected

The `__Host-` prefix mandates `Path=/`. That is **incompatible with this design**: both SPAs send
`credentials: 'include'` on *every* request (hentai0 `api-service.ts:133`; doujins
`lib/http/client.ts`), and doujins has endpoints that are **deliberately anonymous** (`search`,
`content-preferences`, via `omitAuth`). A `Path=/` cookie would (a) silently authenticate calls
that are anonymous by design, and (b) spread CSRF surface across the entire API.

Therefore the cookie is scoped to a path prefix, and AuthKit **MUST** expose the cookie-bearing
endpoints under one:

```
POST /api/v1/session/token      (alias of /api/v1/token)
POST /api/v1/session/logout     (alias of /api/v1/logout)
POST /api/v1/session/current    (alias of /api/v1/sessions/current)
```

New routes are additive (MINOR). The legacy paths keep working unchanged and **never** receive
the cookie. The existing routes do not share a prefix (`/api/v1/token`, `/api/v1/password/login`,
`/api/v1/sessions/current`, `/api/v1/logout`), so no `Path` value could have covered them.

### 2.2 Cookie shadowing (cookie tossing) — the real defense

`gallery.doujins.com` and `media.doujins.com` proxy user-controlled content. An attacker who can
inject there sets `authkit_rt=<attacker's own token>; Domain=.doujins.com; Path=/api/v1/session`.
The browser orders `Cookie` longest-`Path`-first, so the planted value precedes the victim's
host-only cookie and Go's `r.Cookie()` returns the **first** match. The request is genuinely
**same-origin**, so `Sec-Fetch-Site: same-origin` and every origin gate passes. The victim's SPA
then adopts an access token for the *attacker's* account and the user proceeds to enter card data
at `/external-payment` inside it.

`Sec-Fetch-Site` does **not** close this. It closes cross-site and same-site *POST*; a planted
cookie rides a same-origin request. Any claim otherwise is false.

Defenses, all three required:

1. **Authenticated value.** The cookie carries `<token>.<HMAC>` keyed by a server-side
   `RefreshCookieKey`. The server verifies and strips the HMAC before hashing the token. A planted
   cookie fails verification. Server-side storage stays hash-only (`sha256`,
   `service_sessions.go:568-573`) — unchanged.
2. **Fail closed on duplicates.** Read with `r.Cookies()`, not `r.Cookie()`. If more than one
   `authkit_rt` is present: reject the cookie source, log `outcome=cookie_shadowed`, **do not
   revoke the family** (the victim is not the attacker), and emit clears per (3).
3. **Clear both forms.** A host-only `Set-Cookie` cannot delete a `Domain`-scoped cookie. Clears
   MUST be emitted for the host-only form **and** for `Domain=<registrable domain>`, or the
   victim can never recover — every re-login is immediately re-shadowed.

### 2.3 Deleting the cookie (Go footgun)

In `net/http`, `Cookie{MaxAge: 0}` **omits the attribute** and yields a *session cookie*. Only
`MaxAge < 0` serializes `Max-Age=0`. A shared `(value, maxAge)` helper therefore produces a clear
that does not clear.

The API **MUST** be two intent-named functions — `setRefreshCookie(w, value, ttl)` and
`clearRefreshCookie(w)` — with no caller-supplied `maxAge`. `clearRefreshCookie` sets
`MaxAge: -1`. Required test: the serialized header literally contains `Max-Age=0` and an empty
value, and set/clear agree on every other attribute (the existing OIDC `clearStateCookie` omits
`Secure` where `setStateCookie` sets it — do not repeat that).

---

## 3. Two independent switches

The single mode string in the earlier draft was given three mutually exclusive meanings and turned
the kill switch into a mass-logout button. It is split:

| Config | Values | Governs |
| --- | --- | --- |
| `RefreshCookieIssue` | `off` \| `optin` \| `default` | Whether a response **sets** the cookie. |
| `RefreshCookieAccept` | `true` (default) | Whether a request's cookie is **honored**. |
| `RefreshCookieReject` | `false` (emergency only) | Hard off. **Documented effect: mass logout.** |

**Invariant: acceptance is never conditional on issuance mode.** Once a client's only credential
is the cookie, gating acceptance on `issue=off` returns `400 invalid_request` to every browser and
logs out 100% of sessions within one access-token TTL — irrecoverably, because storage is hash-only
so flipping back restores nobody. There is **no** "off-mode clearing drain": orphaned cookies are
inert while acceptance is unconditional, and they clear on the next logout.

`RefreshCookieReject` exists so the destructive action requires reaching for a differently-named
flag whose doc comment says what it does.

Required test: `issue=off` + cookie present + empty body ⇒ **200 with a rotated cookie**, not 400.

---

## 4. Source resolution

Per request to a `/api/v1/session/*` route, in order:

1. If `RefreshCookieReject` — ignore the cookie entirely; body path only.
2. If a valid `authkit_rt` is present (HMAC verified, exactly one, origin gates passed §5) ⇒
   **source = cookie**.
3. Else if `refresh_token` is present in the body ⇒ **source = body**.
4. Else ⇒ `401 invalid_refresh_token`, `outcome=no_credential`, **no cookie clear**.

**Transport is not forced by source.** A request that did not opt in (no
`X-Authkit-Refresh-Delivery: cookie` header) still has its cookie *accepted* — cookie-first is
load-bearing for recovery — but the response also returns `refresh_token` in the body as before.
Forcing cookie-only transport on a client that never asked for it strands the ~5 independent
raw-fetch call sites per app that do not send the header.

---

## 5. CSRF gates — stated honestly

Cookie-bearing routes require **all** of:

1. `Origin` (or `Referer` fallback) matches the configured origin exactly.
2. `Sec-Fetch-Site: same-origin` when the header is present.
3. `Content-Type: application/json` (blocks HTML-form cross-site POSTs).

What these actually deliver: they stop cross-site and same-site POSTs. They **do not** stop
same-origin XSS (§1) and **do not** stop cookie shadowing (§2.2). Do not credit them with either.

`SameSite=Lax` already blocks cross-site POST at the browser; the gates are defense in depth for
clients that omit `Sec-Fetch-*` and for `Referer`-stripped requests.

A failed gate is **`401 invalid_refresh_token` with `outcome=cookie_gate_rejected` and no cookie
clear** — *not* `400 invalid_request`. 400 is terminal client-side (§7); mapping a gate failure to
it logs the user out on a transient proxy misconfiguration.

---

## 6. Rotation, reuse detection, grace

Rotation semantics are unchanged (CAS on `current_token_hash`,
`service_sessions.go:229-248`). Two corrections:

**Grace is a property of the row, not the transport.** A token matching `previous_token_hash`
whose session's `last_used_at` is within `RefreshReuseGrace` (default 10s) is a benign retry:
return the *current* credential, do **not** revoke the family, log
`outcome=reuse_within_grace`. Scoping grace to `source == cookie` breaks the migration exchange's
own two-tab race, which is body-sourced.

**Grace must not blind theft detection.** Outside the window, a previous-hash match revokes the
family as today. Every in-grace hit is logged and alerted on (§12) — the grace suppresses the
*revocation*, never the *signal*.

Note for implementers: `SessionByPreviousTokenHash` filters `revoked_at` but **not**
`expires_at`, while the current-hash lookup filters both (`sessions.sql:22-25`). An expired
session can therefore still trip reuse detection. Align them.

---

## 7. Error matrix and client clear/preserve rules

| Server outcome | Status | Clear cookie? | Client |
| --- | --- | --- | --- |
| rotated | 200 | replace | adopt |
| `no_credential` | 401 | **no** | retryable |
| `invalid_refresh_token` (unknown/expired/revoked) | 401 | **no** | one retry, then re-auth |
| `cookie_gate_rejected` | 401 | **no** | retryable |
| `cookie_shadowed` | 401 | **yes, both forms** (§2.2) | re-auth |
| `reuse_detected` | 401 | yes | re-auth |
| `user_banned` | 403 | yes | terminate |
| rate limited | 429 | **no** | back off, honor `Retry-After` |
| 5xx / network | — | **no** | preserve state, retry |

**Never clear the cookie on the unknown-token 401.** Staleness and death are indistinguishable
there; clearing destroys a still-live jar value. Clearing is reserved for outcomes authoritative
about the whole browser.

This matrix is only real if the client stops collapsing failures. `refreshToken()` currently
returns `{user: null}` for every failure and `tokenScheduler.attemptRefresh` reads that as logout.
It **MUST** return a discriminated outcome — `{ok} | {retryable} | {terminal}` — and the scheduler,
visibility-refresh and api-service interceptor must reschedule on `retryable` and only tear down
on `terminal`. Applies to **both** apps: hentai0's `hooks/auth/refresh-token.ts` **and** doujins'
`AuthSDK.refreshTokensInternal`, which has the identical pre-network guard.

---

## 8. Client rules

1. **"No refresh token" must stop meaning "logged out."** Both apps currently bail before the
   network when no token is readable. Post-flip that is exactly the cookie-only state. They MUST
   still POST with `credentials: 'include'` and an omitted `refresh_token`.
2. **Bootstrap.** With no usable access token, attempt exactly one credentialed
   `POST /api/v1/session/current` under the cross-tab lock. Never gate recovery on a
   script-writable marker (`cookieSessionActive`) — script-writable state is exactly what XSS and
   a cleared `localStorage` destroy.
3. **Single-flight.** One in-flight refresh per browser, cross-tab (existing lock). Losers await
   the winner's result; they never issue their own rotation.
4. **Access token stays in memory only.** No `localStorage` fallback.
5. **Kill switch is header omission, not `body`.** A client backing out omits the delivery header
   (cookie still accepted, §4). Sending `X-Authkit-Refresh-Delivery: body` asserts "I hold a body
   token" and must only be sent by a client that actually does.

---

## 9. Flow coverage

Every credential-minting flow, and what changes:

| Flow | Change |
| --- | --- |
| Password login | Sets cookie when `issue != off`; body token still returned this major. |
| Registration verify — link | Same. Currently returns tokens via redirect; cookie set on that response. |
| Registration verify — code | Same. |
| OIDC callback | Same; `SameSite=Lax` required for the cross-site return (§2). |
| OIDC link / reauth start | Unchanged shape (`{auth_url, state}` is covered surface — MAJOR to alter). |
| Solana / SIWS login + link | Same as password login. |
| Passkeys | Same. |
| 2FA step-up | Unchanged response shape. |
| Delegated / OAT service tokens | **Out of scope** — no browser, no cookie. |
| Popup login (`postMessage`) | Cookie is set on the popup's same-origin response; the nonce'd `postMessage` payload stays for the access token. |
| **`/external-payment` iframe (§9.4)** | Cannot use the cookie — different registrable domain. |

### 9.4 The payment iframe needs a channel, not a refresh

The iframe is cross-origin (`pay.hmovie-moe.us` / `billing.*`) and receives a bearer by
`postMessage`. It structurally cannot refresh: no cookie of ours reaches it. Telling it to "send
the delivery header" is meaningless.

On 401 the iframe **MUST** post `AUTH_TOKEN_REQUEST` to its parent origin; the host page refreshes
on its own origin and posts a fresh `AUTH_TOKEN` back. Nonce and origin allowlist as today.

---

## 10. Migration

Gates **MUST** be provable from data the gatekeeper observes. `refresh_cookie: true` in a response
proves the server *set* a cookie, not that the browser *stored* it — a blocked or evicted cookie
passes that gate and the scrub then destroys the only working credential.

The provable signal: AuthKit echoes the source it actually consumed —
`X-Authkit-Refresh-Source: cookie` — present **only** when `source == cookie` (§4). That is a
round-trip proof of storage.

| Phase | Action | Gate to advance |
| --- | --- | --- |
| 0 | Ship AuthKit with `issue=off`, `accept=true`, new routes, HMAC key configured. | Boot guard passes (§11). |
| 1 | Client change only: outcome-typed `refreshToken()`, bootstrap probe, no-token-still-POSTs, single-flight. Deployed with cookies still off. | No refresh-failure regression for one full session TTL. |
| 2 | `issue=optin`; clients send the delivery header. **On the first response bearing `X-Authkit-Refresh-Source: cookie`, scrub that client's legacy token immediately.** | Cookie-sourced success rate at target. |
| 3 | `issue=default` — cookie set for same-origin-proven requests regardless of header, covering the raw-fetch call sites. | Sustained, then hold one session TTL. |
| 4 | Remove legacy-token *writes* from both clients. | — |
| 5 | (Future MAJOR) drop `refresh_token` from bodies. | Owner decision. |

**The legacy token is not a rollback fallback.** From the first rotation it is a *spent* token —
presenting it trips reuse detection and revokes the family. That is why the scrub happens in
phase 2, on proof, rather than being retained to phase 5 as false insurance.

**Version skew is real.** Two repos, two pins; "same version at all times" is unimplementable.
Rule: a **maximum 24h skew window** between the apps' AuthKit versions, and before each release
audit the version diff specifically for behavior that reads or writes the *shared* session table.

---

## 11. Kill switches

| Tier | Lever | Effect | Mass logout? |
| --- | --- | --- | --- |
| 1 | Client omits delivery header | New issuance reverts to body; cookies still accepted | No |
| 2 | `RefreshCookieIssue=off` | Stops setting cookies; existing ones still work | No |
| 3 | `RefreshCookieReject=true` | Cookies ignored entirely | **Yes** — documented |

Auto-trip on the reuse-rate alert is limited to **tier 1**. Tiers 2 and 3 are human decisions.

**Boot guard:** refuse to start with `issue != off` when `RefreshCookieKey` is unset, or when
`Secure` cannot be derived in a non-dev environment. AuthKit cannot detect a missing
`trusted_proxies` (§14.1) — it must fail loudly on what it *can* check.

---

## 12. Observability

Per `/api/v1/session/*` request, log `outcome` from the §7 enum plus `source`
(`cookie|body|none`). Alert on: `reuse_detected` rate (theft or a client bug),
`cookie_shadowed` (**always investigate** — implies injection on a sibling host),
`reuse_within_grace` rate (grace mis-tuned), and cookie-sourced success rate falling during
phases 2–3.

---

## 13. Test obligations

Each of these is a scenario a reviewer demonstrated breaking an earlier draft. All MUST have a test.

1. `issue=off` + cookie + empty body ⇒ 200 rotated (not 400, not logout).
2. `clearRefreshCookie` serializes `Max-Age=0` with an empty value; set/clear attributes agree.
3. Two `authkit_rt` cookies ⇒ rejected, family **not** revoked, both clear forms emitted.
4. Planted `Domain` cookie with a valid foreign token ⇒ HMAC rejects it.
5. Two tabs refresh concurrently ⇒ both end authenticated, family alive.
6. Rotation commits, response lost, client retries with the old token inside grace ⇒ 200, no revoke.
7. Same retry *outside* grace ⇒ family revoked.
8. Unknown-token 401 ⇒ cookie **not** cleared.
9. Sleep/offline resume past access-token expiry ⇒ recovers via bootstrap probe.
10. Ban ⇒ 403 within one access-token TTL, cookie cleared.
11. `Origin` mismatch ⇒ 401 `cookie_gate_rejected`, no clear, session survives.
12. Pre-upgrade field client (no delivery header) still authenticates through phases 2–3.
13. Iframe 401 ⇒ `AUTH_TOKEN_REQUEST` → parent refresh → `AUTH_TOKEN` delivered.
14. OIDC round trip succeeds with `SameSite=Lax` (regression guard against `Strict`).

---

## 14. Owner decisions

These are product/ops calls, not engineering ones. **This proposal cannot be implemented until
they are answered.**

1. **`trusted_proxies` in every production deployment.** `Secure` derivation and the `Origin`
   gate depend on it. The prod ingress lives in an external gitops repo; AuthKit cannot detect a
   misconfiguration and will silently run the weak variant. Confirm, or accept the risk in writing.
2. **Cross-app SSO between doujins.com and hentai0.com.** Impossible with cookies at any `Domain`
   value — three registrable domains, no shared parent. If it is ever a requirement it needs a
   token-handoff design, and this contract makes handoff *harder*. Confirm it is not on the roadmap.
3. **Brand-flavor and staging hosts** (`doujins.gay`, `doujins.pet`, `hentai0.dev`). Host-only
   cookies mean each origin has its own session, and the OIDC tail always returns to the single
   configured `Frontend.BaseURL` — so a login begun on a flavor host lands on the canonical host
   with the cookie set *there*. Acceptable?
4. **May the payment origin set its own host-only cookie?** It technically can (same binary, same
   origin for its own `/api/`), which would retire the `postMessage` bearer. Separate threat model;
   deliberately out of scope here.
5. **Reuse-grace window** (proposed 10s) and **max version skew** (proposed 24h).
