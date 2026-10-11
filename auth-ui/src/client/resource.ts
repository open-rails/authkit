// Access tokens for other services' APIs (resource servers), by RFC 8693
// token exchange of the AuthKit session at the issuer's token endpoint.
// Bearer tokens unless the app asks for DPoP (RFC 9449) or the issuer
// requires it; a DPoP-bound session's tokens are bound to its key, the only
// one the issuer exchanges it with. Tokens live in memory only.

import { AuthKitError } from "./errors.ts"
import {
  dpopFetch,
  loadDPoPKey,
  type DPoPKey,
  type DPoPNonces,
} from "./dpop.ts"
import { readOAuthError } from "./oauthError.ts"

export type ResourceTokenOptions = {
  // The OAuth client registered for this frontend (token exchange grant).
  clientId: string
  // Default "/oauth2/token": the issuer's token endpoint.
  tokenEndpoint?: string
  // Bind the tokens to this browser's DPoP key. Default false: bearer
  // tokens. An issuer that requires DPoP refuses an unbound exchange
  // (invalid_dpop_proof), and the client then binds anyway.
  dpop?: boolean
  // The IndexedDB name of this frontend's DPoP key. Default
  // "authkit:resource:<clientId>".
  keyName?: string
}

export type ResourceToken = {
  accessToken: string
  tokenType: string
  resource: string
  scope: string[]
  // The group the token is bound to, when one was asked for.
  group?: string
  // Epoch ms.
  expiresAt: number
}

export type ResourceRequest = {
  resource: string
  scope?: string | string[]
  // Binds the token to one group, such as a merchant (group_id): it acts
  // there only, and on root with the user's root permissions. The user must
  // hold a role in the group, or a root role.
  group?: string
}

// The current AuthKit access token, its user and, for a DPoP-bound session,
// its key.
type Session = {
  token: string
  userId: string
  key?: () => Promise<DPoPKey>
} | null

// A cached token and the key its proofs use (null: a bearer token).
type Entry = ResourceToken & {
  userId: string
  proofKey: (() => Promise<DPoPKey>) | null
}

const LEAD_MS = 30_000

const scopes = (s: string | string[] | undefined): string[] =>
  [...new Set(typeof s === "string" ? s.split(/\s+/) : (s ?? []))]
    .filter(Boolean)
    .sort()

export function createResourceTokens(
  options: ResourceTokenOptions,
  deps: {
    fetch: typeof fetch
    // The current AuthKit access token and user, refreshing when needed.
    session: () => Promise<Session>
  }
) {
  const tokenEndpoint = options.tokenEndpoint ?? "/oauth2/token"
  const keyName = options.keyName ?? `authkit:resource:${options.clientId}`
  const nonces: DPoPNonces = new Map()
  const cache = new Map<string, Entry>()
  const pending = new Map<string, Promise<Entry>>()
  const key = (): Promise<DPoPKey> => loadDPoPKey(keyName)
  // Whether exchanges are DPoP-bound: the app's choice, or the issuer's.
  let bind = options.dpop ?? false

  async function exchange(
    r: ResourceRequest,
    s: NonNullable<Session>
  ): Promise<Entry> {
    const scope = scopes(r.scope)
    const body = new URLSearchParams({
      grant_type: "urn:ietf:params:oauth:grant-type:token-exchange",
      client_id: options.clientId,
      subject_token: s.token,
      subject_token_type: "urn:ietf:params:oauth:token-type:access_token",
      resource: r.resource,
    })
    if (scope.length) body.set("scope", scope.join(" "))
    if (r.group) body.set("group_id", r.group)
    const init: RequestInit = {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: body.toString(),
    }
    // A bound session proves its own key; otherwise this frontend's, when
    // bound.
    const proofKey = (): (() => Promise<DPoPKey>) | null =>
      s.key ?? (bind ? key : null)
    const post = async () => {
      const k = proofKey()
      return k
        ? dpopFetch(deps.fetch, await k(), nonces, tokenEndpoint, init)
        : deps.fetch(tokenEndpoint, init)
    }
    let res = await post()
    if (!res.ok) {
      const err = await readOAuthError(res)
      if (proofKey() || err.error !== "invalid_dpop_proof") throw err
      bind = true
      res = await post()
      if (!res.ok) throw await readOAuthError(res)
    }
    const out = (await res.json()) as Record<string, unknown>
    if (typeof out.access_token !== "string")
      throw new Error("token endpoint answered no access_token")
    const expiresIn = typeof out.expires_in === "number" ? out.expires_in : 60
    const tokenType =
      typeof out.token_type === "string" ? out.token_type : "Bearer"
    return {
      accessToken: out.access_token,
      tokenType,
      resource: r.resource,
      scope: typeof out.scope === "string" ? scopes(out.scope) : scope,
      ...(r.group ? { group: r.group } : {}),
      expiresAt: Date.now() + expiresIn * 1000,
      userId: s.userId,
      proofKey: tokenType.toLowerCase() === "dpop" ? (proofKey() ?? key) : null,
    }
  }

  // The token as the app sees it, without the cache's bookkeeping.
  const visible = (e: Entry): ResourceToken => {
    const t: ResourceToken & Partial<Entry> = { ...e }
    delete t.userId
    delete t.proofKey
    return t
  }

  // An access token for r: cached until shortly before it expires, and
  // only for the signed-in user, resource, scopes and group it was
  // exchanged for.
  async function entry(
    r: ResourceRequest,
    opts: { fresh?: boolean } = {}
  ): Promise<Entry> {
    const s = await deps.session()
    if (!s)
      throw new AuthKitError(401, {
        type: "authentication_error",
        code: "unauthenticated",
        message: "Sign in to get a resource token.",
      })
    const id = JSON.stringify([
      s.userId,
      r.resource,
      scopes(r.scope),
      r.group ?? null,
    ])
    const hit = cache.get(id)
    if (!opts.fresh && hit && hit.expiresAt - LEAD_MS > Date.now()) return hit
    let p = pending.get(id)
    if (!p) {
      p = exchange(r, s)
        .then((t) => {
          cache.set(id, t)
          return t
        })
        .finally(() => pending.delete(id))
      pending.set(id, p)
    }
    return p
  }

  const getResourceToken = async (
    r: ResourceRequest,
    opts: { fresh?: boolean } = {}
  ): Promise<ResourceToken> => visible(await entry(r, opts))

  // fetch with token: a DPoP-bound one with a proof of its key (RFC 9449
  // §7), else as a bearer token (RFC 6750 §2.1).
  async function send(
    input: string | URL,
    init: RequestInit,
    token: Entry
  ): Promise<Response> {
    if (token.proofKey)
      return dpopFetch(
        deps.fetch,
        await token.proofKey(),
        nonces,
        input,
        init,
        token.accessToken
      )
    const headers = new Headers(init.headers)
    headers.set("Authorization", `Bearer ${token.accessToken}`)
    return deps.fetch(input, { ...init, headers })
  }

  // fetch for a resource server's API with its token. A 401 invalid_token
  // is retried once with a freshly exchanged token. Never throws on HTTP
  // status.
  async function resourceFetch(
    input: string | URL,
    init: RequestInit & ResourceRequest
  ): Promise<Response> {
    const { resource, scope, group, ...rest } = init
    const r = { resource, scope, group }
    let token = await entry(r)
    let res = await send(input, rest, token)
    if (
      res.status === 401 &&
      /error="invalid_token"/.test(res.headers.get("WWW-Authenticate") ?? "")
    ) {
      token = await entry(r, { fresh: true })
      res = await send(input, rest, token)
    }
    return res
  }

  return {
    getResourceToken,
    resourceFetch,
    // Drops every token (sign-out); the DPoP key stays for the next user.
    clear: () => cache.clear(),
  }
}
