# Rate limits and ephemeral state

## Who is limited

Every route has a per-client-address bucket (`DefaultRateLimits`), keyed by the
client IP. IPv6 clients are keyed by their /64, since one subscriber usually
holds a whole /64.

- **High-entropy secrets** (passwords, API keys, refresh tokens, signed
  challenges): per address only. Password login, `/step-up/password` and every
  password re-check on a sensitive action share this rule. No per-account limit
  exists, so a stranger's wrong guesses cannot lock an owner out; the guessing
  address is blocked, even with the right password, until its window passes.
- **Low-entropy secrets** (email/SMS verification codes, passwordless codes,
  2FA codes): per address plus a per-account (or per-challenge) bucket, because
  a one-in-a-million code falls to enough addresses. Outstanding codes are
  also invalidated after five wrong guesses. A 2FA challenge is keyed by its
  first-factor proof, so a stranger who knows only a user id cannot spend the
  owner's budget.
- **Sends** (codes, resets, invitations, registrations): per address plus per
  destination, so one address cannot be flooded from many clients.

## Where the state lives

Codes, attempt counters and OIDC/SIWS login state live in Postgres and are
shared by every replica. Rate-limit budgets are shared through
`authhttp.Config.Redis` (Redis or Garnet, keys under `RedisKeyPrefix`). Without
it each process keeps its own budgets, so the effective limit is multiplied by
the replica count; the per-code attempt caps still hold.
