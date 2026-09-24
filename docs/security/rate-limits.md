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

With `Deps.Redis` (Redis or Garnet), limits, codes and OIDC/SIWS login state are
shared by every replica. Without it AuthKit uses process memory automatically
and logs one startup warning. That is correct for a single replica only: with
several, each keeps its own budgets and a login started on one cannot finish on
another. Multi-replica deployments must configure Redis or Garnet.

A custom `Deps.EphemeralStore` backs codes and pending registrations but not the
HTTP limiter or OIDC/SIWS state, which then stay in memory unless
`authhttp.Config.Redis` is set.
