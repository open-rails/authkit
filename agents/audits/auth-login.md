# Authentication / Login Methods — Audit

Focused correctness-and-integrity audit of AuthKit's **login surface**: password
(+username/phone), passwordless, password reset (email/phone), email/phone verification,
OIDC + OAuth2 social login, token issuance, sessions, step-up, passkeys (WebAuthn),
TOTP/2FA + mandatory-2FA, and SIWS/Solana wallet login.

**Grounded at commit `d97a0c8`.** Every verdict was re-read against the actual code (handlers +
service callees + queries + DDL), not taken from a summary. Evidence is `file:line`.

Verify gates: `go build ./...`, `go vet ./...`, `task test-fast` (race, DB-free),
`task test` (DB-backed), `task sqlc` / `task sqlc-check` (after any query/schema edit).

Markers: **[confirmed]** = read end-to-end · **[decision]** = needs a policy call · **[by-design]** = intentional, not a finding.

## Surface & reachability (this is a library other projects import)

"Not called in this repo" does **not** prove a symbol is dead — external consumers can call any
**exported** identifier. The consumer-facing surface is: the **HTTP wire contract** (route JSON +
status codes), the `embedded` facade + its aliased types/constants (`embedded/aliases.go`), exported
**sentinel errors** (`errors.go`), the **`authkit.Client` contract** (`client.go`/`contract.go`) and
its generated RPC (`server/`, `remote/`). `internal/authcore/*` is import-forbidden externally, so an
unexported symbol there with no in-repo caller is genuinely dead; an exported one is not. Plans that
break this surface (forward-only is waived by the operator, 2026-06-26) say so and flag it for
`BREAKING.md`/`SEMVER.md` — they do **not** justify a removal as "unused." (Same boundary the
registration-verification audit uses.)

**Active issues (`agents/progress.md`) that overlap this batch** — reconciled in the plans, see
`plans/README.md` → "Active-issue coordination": **#143** deletes `WithSolanaDomain` (reframes the
F12 plan toward `Frontend.BaseURL` derivation); **#148** replaces `RequireMFAEnrollment` with
`TwoFactor.Mode` (F9's guard keys on the new `Mode`); **#144** (done) already renamed `OIDCReturnPath`
in the callback files (F1's refactor preserves it); **#146** reshapes the step-up gate (F10); **#147**
relocates registration-verification config (A6). Public-surface-breaking fixes ride #143's single
consumer bump.

---

## Confirmed findings → plans

| ID | Finding | Plan |
|----|---------|------|
| F1 | OIDC browser callback swallows the load-bearing provider-link / email-verified / username writes (`_ =`); the OAuth2 sibling fails closed and documents why (orphan user / dup account / link-required dead-end, #88). `http/oidc_browser.go:149,201` vs `http/oauth2_browser.go:384,430`. | 014 |
| F2 | Email/SMS 2FA codes consumed non-atomically (`ephemGetJSON`+`ephemDel`) while the documented rule (`ephemeral.go:96`) and every sibling (passkey ceremony, reset token/session, TOTP step, backup code) use atomic `Consume`. Same valid code can authenticate two concurrent requests. `ephemeral_data.go:484,502`. | 015 |
| F3 | SIWS login/link error→status mapping via `contains(err.Error(), …)`; `"domain validation failed"` has no branch (falls to generic 401). A reworded error silently changes HTTP behavior. `http/solana_siws.go:138-150,232-244`. | 016 |
| F4 | Email/phone-change error mapping via `strings.Contains(msg, "same as current" / "already in use")`; sentinels already exist (`ErrEmailInUse`, `ErrPhoneInUse`). `http/email_verify.go:64-72`; `http/phone_verify.go`. | 011 (REG-4) |
| F5 | OIDC step-up stamps `pwd` auth method (`MarkSessionAuthenticated` default) though no password was used; OAuth2 step-up correctly stamps `oauth`. AMR/assurance-claim integrity. `http/step_up.go:226` vs `oauth2_browser.go:355`. | 017 |
| F6 | SIWS `chain_id` is read into the request (`solana_siws.go:23`) but never bound or validated; `verifySIWSChallenge` never compares the signed message's chain to the server's. Cross-network replay + dead input contract. `service_solana.go:271-307`. | 018 |
| F7 | `LinkProviderByIssuer` runs `UserProviderDeleteOtherSubjects` then `UserProviderUpsertByIssuer` as two non-transactional statements, and the upsert's `ON CONFLICT (issuer,subject) DO UPDATE` rewrites a row even when it belongs to a **different** `user_id` (cross-user write; pre-check is TOCTOU). `service.go:3912-3939`; `providers.sql.go:301-307`. | 019 |
| F8 | `finishPasswordReset` discards the `RevokeAllSessions` error (`_ =`) and the rotation is non-atomic: password can be rotated while old refresh sessions survive, fully silently. `service.go:1612-1624` (also `ChangePassword`). | 020 |
| F9 | A mandatory-2FA user (`opts.RequireMFAEnrollment`) can delete their last/only factor; `Disable2FAFactorWithRemovedRoles` has no guard, then every new/refreshed session is blocked with `2fa_enrollment_required`. Self-lockout. `service.go:4287-4296`; `http/user_2fa.go:246`. | 021 |
| F10 | OAuth2 step-up has no re-auth freshness check (the OIDC path enforces `max_age=0`+`auth_time` via `validOIDCStepUpTime`); it is presence-only. `oauth2_browser.go:346-358`. **[decision → fix defensively]** | 022 |
| F11 | `Verify2FACode` with no `factor_id` only tries the default factor (`twoFactorFactor` returns default-or-`factors[0]`); a valid code for a non-default factor is rejected. Fails closed. `service.go:4598,4685-4714`. | 023 |
| F12 | SIWS domain binding is self-referential when `WithSolanaDomain` is unset — the challenge domain is taken from the client `Origin`/`Host` and verification compares against that same value, so the anti-phishing anchor provides no protection in the default config. `http/solana_siws.go:40-60`. **[decision → fix defensively]** | 024 |

### Forward-only / structural (operator asked for these explicitly; backward compat waived)

| ID | Change | Plan |
|----|--------|------|
| A2 | **Transactional create-user-with-provider-link** — social-login new-user path does `CreateUser` then `LinkProviderByIssuer` as two writes; a failed link leaves an orphan user (authkit #88). One transaction. Coordinates with REG-3 (plan 010, native-registration atomicity). `oauth2_browser.go:427-430`. | 025 |
| A5 | **Retire the divergent slug-based provider-link path** — `LinkProvider`/`getProviderLinkBySlug`/`UserProviderInsertSimple`/`ProviderLinkBySlug` resolve on `(provider_slug, subject)` with a plain `INSERT` (no `ON CONFLICT`), diverging from the issuer-based path; for one identity they can resolve a *different* user. Removal is a **deliberate breaking** public-API change (these are on the client contract), justified by the hazard, **not** by "unused." `service.go:3654-3655,3670-3671,3967-3987`. | 026 |
| A6 | **Config the verification cutoff** — replace the hardcoded `2025-01-01` literal gating login-time verification enforcement with an explicit `Options` field (or remove the gate). `password_login_post.go:179-180`. | 027 |

Note: **F4 is the same finding as REG-4** (registration-verification batch) — fixed by its plan
`011-change-request-error-sentinels`, not duplicated here; plan 016 covers only the SIWS half of F3.

---

## Considered and rejected / downgraded (do not re-audit)

- **Verify-request enumeration (404/409/202)** — `http/email_verify.go:83`, `phone_verify.go`. Largely
  **redundant**: `/register/availability` (public, rate-limited) already exposes in-use state by design
  (`register_availability.go`). The only novel leak is verified-vs-unverified. Not worth a contract break.
- **Login timing oracle** — `PasswordLogin` returns before hashing on user-miss (`service.go:1054`). Real but
  well-known; per-identifier rate-limiting (`rateLimitedByIdentifier`) mitigates. Marginal; a dummy-hash
  compare adds CPU to every failed login. Deferred.
- **Soft-deleted/banned users can request a reset & set a password** — `RequestPasswordReset`/`finishPasswordReset`
  skip `ensureUserAccess` (`service.go:1516,1612`). **No login bypass**: `PasswordLogin`/`*ByUserID` gate via
  `ensureUserAccess` (`service.go:1058,1112`). Hygiene only. Optional add-on to plan 020.
- **Hardcoded `2025-01-01` verification cutoff** — `password_login_post.go:179-180`. Real magic-date cliff,
  but flipping it forces legacy/imported accounts to verify → **product decision**, not a mechanical fix.
- **Concurrent wallet/provider link returns a false 200 to the loser** — `service_solana.go:217`. The DB unique
  constraint prevents takeover; only the loser's response is wrong. Folded into plan 019.
- **Slug-based link helpers** — **promoted to a plan**, not rejected: see A5 / plan 026 above. (The
  earlier "needs caller confirmation" framing was wrong for a library — they're exported contract
  methods; removal is a deliberate breaking change justified by the divergence hazard, not by non-use.)
- **Passkey login hardcodes `"mfa"`** (`passkeys.go:255`) — **by-design**: user-verification is enforced at
  `passkeys.go:246`, so a UV passkey legitimately satisfies MFA. Document, don't change.
- **`EnableTOTP2FADefault` non-atomic pending-secret read** (`totp.go:66-86`) — idempotent upsert; minor
  replay-within-window only. Low.

## Confirmed sound (spot-checked, not findings)

OIDC state single-use (`GETDEL` / locked delete), `id_token` issuer+audience+nonce validation, account-takeover-by-email
guard (C-2), refresh-rotation CAS, logout/per-session ownership scoping, SIWS nonce single-use + address binding +
server-authoritative expiry + pubkey/address consistency, WebAuthn challenge single-use + signCount clone guard, TOTP
step monotonic guard, backup-code atomic removal, factor/passkey ownership scoping on verify/delete/rename, `open-redirect`
sanitisation on step-up `return_to`, `redirect_uri` derived from trusted `BaseURL`.
