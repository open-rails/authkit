// Access tokens for other services' APIs (resource servers), by RFC 8693
// token exchange of the AuthKit session at the issuer's token endpoint,
// bound to this browser's DPoP key. Tokens live in memory only.

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
  // The IndexedDB name of this frontend's DPoP key. Default
  // "authkit:resource:<clientId>".
  keyName?: string
}

export type ResourceToken = {
  accessToken: string
  tokenType: string
  resource: string
  scope: string[]
  // Epoch ms.
  expiresAt: number
}

export type ResourceRequest = {
  resource: string
  scope?: string | string[]
}

type Session = { token: string; userId: string } | null

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
  const cache = new Map<string, ResourceToken & { userId: string }>()
  const pending = new Map<string, Promise<ResourceToken>>()
  const key = (): Promise<DPoPKey> => loadDPoPKey(keyName)

  async function exchange(
    r: ResourceRequest,
    s: NonNullable<Session>
  ): Promise<ResourceToken> {
    const scope = scopes(r.scope)
    const body = new URLSearchParams({
      grant_type: "urn:ietf:params:oauth:grant-type:token-exchange",
      client_id: options.clientId,
      subject_token: s.token,
      subject_token_type: "urn:ietf:params:oauth:token-type:access_token",
      resource: r.resource,
    })
    if (scope.length) body.set("scope", scope.join(" "))
    const res = await dpopFetch(
      deps.fetch,
      await key(),
      nonces,
      tokenEndpoint,
      {
        method: "POST",
        headers: { "Content-Type": "application/x-www-form-urlencoded" },
        body: body.toString(),
      }
    )
    if (!res.ok) throw await readOAuthError(res)
    const out = (await res.json()) as Record<string, unknown>
    if (typeof out.access_token !== "string")
      throw new Error("token endpoint answered no access_token")
    const expiresIn = typeof out.expires_in === "number" ? out.expires_in : 60
    return {
      accessToken: out.access_token,
      tokenType: typeof out.token_type === "string" ? out.token_type : "DPoP",
      resource: r.resource,
      scope: typeof out.scope === "string" ? scopes(out.scope) : scope,
      expiresAt: Date.now() + expiresIn * 1000,
    }
  }

  // An access token for r: cached until shortly before it expires, and
  // only for the signed-in user it was exchanged for.
  async function getResourceToken(
    r: ResourceRequest,
    opts: { fresh?: boolean } = {}
  ): Promise<ResourceToken> {
    const s = await deps.session()
    if (!s)
      throw new AuthKitError(401, {
        type: "authentication_error",
        code: "unauthenticated",
        message: "Sign in to get a resource token.",
      })
    const id = `${s.userId} ${r.resource} ${scopes(r.scope).join(" ")}`
    const hit = cache.get(id)
    if (!opts.fresh && hit && hit.expiresAt - LEAD_MS > Date.now()) return hit
    let p = pending.get(id)
    if (!p) {
      p = exchange(r, s)
        .then((t) => {
          cache.set(id, { ...t, userId: s.userId })
          return t
        })
        .finally(() => pending.delete(id))
      pending.set(id, p)
    }
    return p
  }

  // fetch for a resource server's API with its token and a DPoP proof. A
  // 401 invalid_token is retried once with a freshly exchanged token. Never
  // throws on HTTP status.
  async function resourceFetch(
    input: string | URL,
    init: RequestInit & ResourceRequest
  ): Promise<Response> {
    const { resource, scope, ...rest } = init
    const r = { resource, scope }
    let token = await getResourceToken(r)
    let res = await dpopFetch(
      deps.fetch,
      await key(),
      nonces,
      input,
      rest,
      token.accessToken
    )
    if (
      res.status === 401 &&
      /error="invalid_token"/.test(res.headers.get("WWW-Authenticate") ?? "")
    ) {
      token = await getResourceToken(r, { fresh: true })
      res = await dpopFetch(
        deps.fetch,
        await key(),
        nonces,
        input,
        rest,
        token.accessToken
      )
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
