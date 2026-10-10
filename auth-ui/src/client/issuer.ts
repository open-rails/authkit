// An OAuth 2.0 / OIDC client of an external issuer (#431): the app signs
// users in at the issuer (authorization code + PKCE S256 + RFC 8707
// resource) and calls APIs with the issuer's access tokens. It works with
// any OIDC issuer. Tokens are bearer tokens unless the app asks for DPoP
// (RFC 9449) or the issuer requires it.
//
// Access tokens stay in memory. The rotating refresh token (bound to the
// non-extractable DPoP key when DPoP is used) is kept in IndexedDB, so a
// reload restores the session without a redirect; never in localStorage.

import type { AuthSession } from "./client.ts"
import {
  b64url,
  deleteDPoPKey,
  dpopFetch,
  loadDPoPKey,
  utf8,
  type DPoPKey,
  type DPoPNonces,
} from "./dpop.ts"
import { idbDelete, idbGet, idbPut } from "./idb.ts"
import { decodeAccessClaims, type AccessClaims } from "./jwt.ts"
import { OAuthError, readOAuthError } from "./oauthError.ts"
import { asksForStepUp } from "./stepUp.ts"

export type IssuerClientOptions = {
  // The issuer identifier; its metadata is at
  // <issuer>/.well-known/openid-configuration.
  issuer: string
  clientId: string
  // This app's registered callback (absolute, or relative to the page).
  redirectUri: string
  // RFC 8707 resource the access tokens are for (the API's identifier).
  resource?: string
  // Default "openid profile email".
  scope?: string | string[]
  postLogoutRedirectUri?: string
  // Bind the session to a DPoP key (RFC 9449). Default false: bearer
  // tokens. An issuer that requires DPoP refuses an unbound token request
  // (invalid_dpop_proof), and the client then binds the session anyway.
  dpop?: boolean
  // Keep the refresh token across reloads (IndexedDB). Default true.
  persist?: boolean
  // Refresh this long before access-token expiry. Default 60.
  refreshLeadSeconds?: number
  fetch?: typeof fetch
}

// The signed-in user, from the issuer's ID token.
export type IssuerUser = {
  sub: string
  name?: string
  preferredUsername?: string
  email?: string
  emailVerified?: boolean
}

export type IssuerSignInOptions = {
  prompt?: "none" | "login"
  // 0 asks for a fresh sign-in (a step-up).
  maxAge?: number
  loginHint?: string
  // Where the app goes after the callback; returned by completeSignIn.
  returnTo?: string
  // Sign in in a popup instead of navigating away. Call from a click.
  popup?: boolean
}

export type IssuerCallback =
  | { kind: "signed_in"; returnTo?: string }
  // A popup's callback, handed to the window that opened it.
  | { kind: "popup" }

type Metadata = {
  issuer: string
  authorization_endpoint: string
  token_endpoint: string
  end_session_endpoint?: string
  revocation_endpoint?: string
  dpop_signing_alg_values_supported?: string[]
  authorization_response_iss_parameter_supported?: boolean
}

type Pending = {
  state: string
  verifier: string
  nonce: string
  redirectUri: string
  returnTo?: string
}

// bound: the session's tokens are DPoP-bound (token_type DPoP), so its
// refresh token is redeemed with the same key (RFC 9449 §5).
type Stored = {
  refreshToken: string
  idToken?: string
  user?: IssuerUser
  bound?: boolean
}

type TokenAnswer = {
  access_token: string
  token_type?: string
  expires_in?: number
  refresh_token?: string
  id_token?: string
}

const MESSAGE = "authkit:issuer-callback"
const MAX_TIMER = 2_147_483_647
const POPUP_TIMEOUT_MS = 5 * 60_000

const random = (bytes: number) => {
  const arr = new Uint8Array(bytes)
  crypto.getRandomValues(arr)
  return b64url(arr)
}

const decode = (jwt: string): Record<string, unknown> | null =>
  decodeAccessClaims(jwt)

const userOf = (claims: Record<string, unknown>): IssuerUser => ({
  sub: String(claims.sub ?? ""),
  name: typeof claims.name === "string" ? claims.name : undefined,
  preferredUsername:
    typeof claims.preferred_username === "string"
      ? claims.preferred_username
      : undefined,
  email: typeof claims.email === "string" ? claims.email : undefined,
  emailVerified:
    typeof claims.email_verified === "boolean"
      ? claims.email_verified
      : undefined,
})

export type IssuerClient = ReturnType<typeof createIssuerClient>

export function createIssuerClient(options: IssuerClientOptions) {
  const issuer = options.issuer.replace(/\/+$/, "")
  const id = `${issuer}|${options.clientId}`
  const prefer = options.dpop ?? false
  const persist = options.persist ?? true
  const leadMs = (options.refreshLeadSeconds ?? 60) * 1000
  const scope = (
    typeof options.scope === "string"
      ? options.scope.split(/\s+/)
      : (options.scope ?? ["openid", "profile", "email"])
  ).filter(Boolean)
  const doFetch: typeof fetch = (...args) =>
    (options.fetch ?? globalThis.fetch)(...args)
  const nonces: DPoPNonces = new Map()
  const keyName = `authkit:issuer:${id}`
  const txKey = (state: string) => `authkit:issuer:tx:${id}:${state}`
  const redirectUri = () =>
    new URL(options.redirectUri, globalThis.location?.href).toString()

  let session: AuthSession = { status: "loading" }
  let user: IssuerUser | null = null
  let idToken: string | undefined
  let refreshToken: string | undefined
  // Whether the session's tokens are DPoP-bound.
  let bound = prefer
  let generation = 0
  let timer: ReturnType<typeof setTimeout> | null = null
  let refreshing: Promise<boolean> | null = null
  let exchanging = false
  let started = false
  const listeners = new Set<() => void>()
  const waiters: (() => void)[] = []

  const emit = (next: AuthSession) => {
    session = next
    if (next.status !== "loading") waiters.splice(0).forEach((w) => w())
    for (const l of listeners) {
      try {
        l()
      } catch {
        // one failing subscriber must not starve the rest
      }
    }
  }

  // --- issuer metadata ------------------------------------------------------

  let meta: Promise<Metadata> | null = null
  const metadata = (): Promise<Metadata> => {
    if (!meta) {
      meta = (async () => {
        const res = await doFetch(`${issuer}/.well-known/openid-configuration`)
        if (!res.ok) throw new Error(`issuer metadata: HTTP ${res.status}`)
        const m = (await res.json()) as Metadata
        if (m.issuer !== issuer)
          throw new Error(`issuer metadata names ${m.issuer}, not ${issuer}`)
        return m
      })()
      meta.catch(() => (meta = null))
    }
    return meta
  }

  const key = (): Promise<DPoPKey> | null =>
    bound ? loadDPoPKey(keyName) : null

  // --- persistence ------------------------------------------------------------

  const load = async (): Promise<Stored | undefined> =>
    persist
      ? idbGet<Stored>("issuer-sessions", id).catch(() => undefined)
      : refreshToken
        ? { refreshToken, idToken, user: user ?? undefined }
        : undefined

  const save = async (s: Stored | null) => {
    if (!persist) return
    await (
      s ? idbPut("issuer-sessions", id, s) : idbDelete("issuer-sessions", id)
    ).catch(() => undefined)
  }

  // Serializes refresh-token rotation across tabs: two tabs redeeming one
  // token would revoke its family.
  const locked = <T>(fn: () => Promise<T>): Promise<T> =>
    typeof navigator !== "undefined" && navigator.locks
      ? (navigator.locks.request(`authkit:issuer:${id}`, fn) as Promise<T>)
      : fn()

  // --- token endpoint -------------------------------------------------------

  async function token(params: Record<string, string>): Promise<TokenAnswer> {
    const m = await metadata()
    const body = new URLSearchParams({ ...params, client_id: options.clientId })
    if (options.resource && !body.has("resource"))
      body.set("resource", options.resource)
    const init: RequestInit = {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: body.toString(),
    }
    const post = async () => {
      const k = key()
      return k
        ? dpopFetch(doFetch, await k, nonces, m.token_endpoint, init)
        : doFetch(m.token_endpoint, init)
    }
    let res = await post()
    if (!res.ok) {
      const err = await readOAuthError(res)
      // The issuer requires DPoP: bind the session and ask again.
      if (bound || err.error !== "invalid_dpop_proof") throw err
      bound = true
      res = await post()
      if (!res.ok) throw await readOAuthError(res)
    }
    const out = (await res.json()) as TokenAnswer
    if (typeof out.access_token !== "string")
      throw new OAuthError(res.status, "server_error", "no access_token")
    bound = out.token_type?.toLowerCase() === "dpop"
    return out
  }

  async function commit(t: TokenAnswer, gen: number) {
    if (gen !== generation) return
    const claims = (decodeAccessClaims(t.access_token) ?? {}) as AccessClaims
    if (t.id_token) {
      idToken = t.id_token
      user = userOf(decode(t.id_token) ?? {})
    }
    if (t.refresh_token) refreshToken = t.refresh_token
    const expiresAt =
      typeof claims.exp === "number"
        ? claims.exp * 1000
        : Date.now() + (t.expires_in ?? 300) * 1000
    if (refreshToken)
      await save({ refreshToken, idToken, user: user ?? undefined, bound })
    if (gen !== generation) return
    emit({
      status: "authenticated",
      accessToken: t.access_token,
      userId: String(claims.sub ?? user?.sub ?? ""),
      claims,
      expiresAt,
    })
    schedule(expiresAt)
  }

  function schedule(expiresAt: number) {
    if (timer) clearTimeout(timer)
    timer = null
    if (!refreshToken) return
    const wait = Math.min(
      Math.max(0, expiresAt - leadMs - Date.now()),
      MAX_TIMER
    )
    timer = setTimeout(() => void refresh(), wait)
  }

  function clear(reason: "initial" | "signed_out" | "expired") {
    generation++
    if (timer) clearTimeout(timer)
    timer = null
    refreshToken = undefined
    idToken = undefined
    user = null
    emit({ status: "anonymous", reason, continuation: null })
  }

  // Rotates the refresh token for fresh tokens; false when there is none or
  // the issuer refused it (the session then ends as expired).
  function refresh(): Promise<boolean> {
    if (refreshing) return refreshing
    const gen = generation
    refreshing = locked(async () => {
      const stored = await load()
      if (!stored?.refreshToken) return false
      refreshToken = stored.refreshToken
      bound = stored.bound ?? false
      idToken = stored.idToken ?? idToken
      user = stored.user ?? user
      try {
        await commit(
          await token({
            grant_type: "refresh_token",
            refresh_token: stored.refreshToken,
          }),
          gen
        )
        return gen === generation
      } catch (err) {
        if (err instanceof OAuthError && err.status < 500) {
          await save(null)
          if (gen === generation) clear("expired")
          return false
        }
        // a network or server failure: try again shortly
        if (gen === generation && session.status === "authenticated")
          timer = setTimeout(() => void refresh(), 5_000)
        return false
      }
    }).finally(() => (refreshing = null))
    return refreshing
  }

  // --- sign-in ----------------------------------------------------------------

  async function authorizeURL(
    opts: IssuerSignInOptions,
    popup: boolean
  ): Promise<{ url: string; pending: Pending }> {
    const m = await metadata()
    const pending: Pending = {
      state: `${popup ? "p" : "r"}.${random(16)}`,
      verifier: random(32),
      nonce: random(16),
      redirectUri: redirectUri(),
      returnTo: opts.returnTo,
    }
    const q = new URLSearchParams({
      response_type: "code",
      client_id: options.clientId,
      redirect_uri: pending.redirectUri,
      scope: scope.join(" "),
      state: pending.state,
      nonce: pending.nonce,
      code_challenge: b64url(
        await crypto.subtle.digest("SHA-256", utf8(pending.verifier))
      ),
      code_challenge_method: "S256",
    })
    if (options.resource) q.set("resource", options.resource)
    if (opts.prompt) q.set("prompt", opts.prompt)
    if (opts.maxAge !== undefined) q.set("max_age", String(opts.maxAge))
    if (opts.loginHint) q.set("login_hint", opts.loginHint)
    // A new sign-in starts from the app's choice; dpop_jkt binds its code to
    // the key (RFC 9449 §10).
    bound = prefer
    const k = key()
    if (k) q.set("dpop_jkt", (await k).thumbprint)
    const url = new URL(m.authorization_endpoint)
    for (const [name, value] of q) url.searchParams.set(name, value)
    return { url: url.toString(), pending }
  }

  // Sends the browser to the issuer (the default) or, with popup, signs in
  // in a popup and resolves once the tokens are in.
  async function signIn(opts: IssuerSignInOptions = {}): Promise<void> {
    if (opts.popup) return signInWithPopup(opts)
    const { url, pending } = await authorizeURL(opts, false)
    sessionStorage.setItem(txKey(pending.state), JSON.stringify(pending))
    location.assign(url)
  }

  async function signInWithPopup(opts: IssuerSignInOptions): Promise<void> {
    const popup = window.open(
      "about:blank",
      "authkit_issuer",
      "popup=yes,width=520,height=680"
    )
    if (!popup) throw new OAuthError(0, "popup_blocked")
    let pending: Pending
    try {
      const built = await authorizeURL(opts, true)
      pending = built.pending
      popup.location.href = built.url
    } catch (err) {
      popup.close()
      throw err
    }
    const href = await new Promise<string>((resolve, reject) => {
      const done = (fn: () => void) => {
        window.removeEventListener("message", onMessage)
        clearInterval(poll)
        clearTimeout(deadline)
        fn()
      }
      // Only this app's own callback page, in the popup we opened, for the
      // state we sent.
      const onMessage = (e: MessageEvent) => {
        const data = e.data as { type?: unknown; url?: unknown } | null
        if (
          e.origin !== location.origin ||
          e.source !== popup ||
          data?.type !== MESSAGE ||
          typeof data.url !== "string"
        )
          return
        if (new URL(data.url).searchParams.get("state") !== pending.state)
          return
        done(() => resolve(data.url as string))
      }
      window.addEventListener("message", onMessage)
      const poll = setInterval(() => {
        if (popup.closed) done(() => reject(new OAuthError(0, "popup_closed")))
      }, 500)
      const deadline = setTimeout(
        () => done(() => reject(new OAuthError(0, "popup_timeout"))),
        POPUP_TIMEOUT_MS
      )
    })
    popup.close()
    await finish(new URL(href), pending)
  }

  // Finishes a sign-in on the callback page: null when href is not a
  // callback. In a popup it hands the answer to the opener and closes. An
  // issuer error (login_required, access_denied, ...) throws OAuthError.
  async function completeSignIn(
    href: string = location.href
  ): Promise<IssuerCallback | null> {
    const url = new URL(href)
    const state = url.searchParams.get("state")
    if (
      !state ||
      !(url.searchParams.has("code") || url.searchParams.has("error"))
    )
      return null
    if (state.startsWith("p.") && window.opener && window.opener !== window) {
      ;(window.opener as Window).postMessage(
        { type: MESSAGE, url: href },
        location.origin
      )
      window.close()
      return { kind: "popup" }
    }
    const raw = sessionStorage.getItem(txKey(state))
    sessionStorage.removeItem(txKey(state))
    if (href === location.href) {
      const clean = new URL(href)
      for (const p of ["code", "state", "iss", "error", "error_description"])
        clean.searchParams.delete(p)
      history.replaceState(history.state, "", clean)
    }
    try {
      if (!raw)
        throw new OAuthError(400, "invalid_request", "unknown or reused state")
      const pending = JSON.parse(raw) as Pending
      await finish(url, pending)
      return { kind: "signed_in", returnTo: pending.returnTo }
    } catch (err) {
      // Nothing else will settle a session no restore is running for.
      if (session.status === "loading" && !refreshing) clear("initial")
      throw err
    }
  }

  async function finish(url: URL, pending: Pending) {
    const m = await metadata()
    const iss = url.searchParams.get("iss")
    if (
      iss !== null
        ? iss !== m.issuer
        : m.authorization_response_iss_parameter_supported
    )
      throw new OAuthError(
        400,
        "invalid_request",
        "the response is from another issuer"
      )
    const error = url.searchParams.get("error")
    if (error)
      throw new OAuthError(
        400,
        error,
        url.searchParams.get("error_description") ?? undefined
      )
    const code = url.searchParams.get("code")
    if (!code) throw new OAuthError(400, "invalid_request", "no code")
    exchanging = true
    const gen = ++generation
    try {
      const t = await token({
        grant_type: "authorization_code",
        code,
        redirect_uri: pending.redirectUri,
        code_verifier: pending.verifier,
      })
      if (scope.includes("openid")) {
        const id = t.id_token ? decode(t.id_token) : null
        const aud = id?.aud
        if (
          !id ||
          id.iss !== m.issuer ||
          !(
            aud === options.clientId ||
            (Array.isArray(aud) && aud.includes(options.clientId))
          ) ||
          id.nonce !== pending.nonce ||
          typeof id.exp !== "number" ||
          id.exp * 1000 < Date.now()
        )
          throw new OAuthError(
            400,
            "invalid_grant",
            "the ID token does not answer this sign-in"
          )
      }
      refreshToken = undefined
      await commit(t, gen)
    } catch (err) {
      if (gen === generation && session.status === "loading") clear("initial")
      throw err
    } finally {
      exchanging = false
    }
  }

  // --- session ------------------------------------------------------------------

  // Restores the session from the kept refresh token. Returns stop.
  function start(): () => void {
    if (!started) {
      started = true
      if (!exchanging && session.status === "loading")
        void refresh().then((ok) => {
          if (!ok && !exchanging && session.status === "loading")
            clear("initial")
        })
    }
    return stop
  }

  function stop() {
    started = false
    if (timer) clearTimeout(timer)
    timer = null
  }

  const ready = (): Promise<void> =>
    session.status === "loading"
      ? new Promise((resolve) => waiters.push(resolve))
      : Promise.resolve()

  const accessToken = () =>
    session.status === "authenticated" ? session.accessToken : null

  // fetch for the API with the access token (and a DPoP proof); a 401
  // invalid_token is retried once after a refresh (a step-up is not). Never
  // throws on status.
  async function authFetch(
    input: string | URL,
    init: RequestInit = {}
  ): Promise<Response> {
    await ready()
    const attempt = async (at: string | null) => {
      const k = key()
      if (at && k) return dpopFetch(doFetch, await k, nonces, input, init, at)
      const headers = new Headers(init.headers)
      if (at) headers.set("Authorization", `Bearer ${at}`)
      return doFetch(input, { ...init, headers })
    }
    const at = accessToken()
    let res = await attempt(at)
    if (
      at &&
      res.status === 401 &&
      !/use_dpop_nonce/.test(res.headers.get("WWW-Authenticate") ?? "") &&
      !(await asksForStepUp(res)) &&
      (await refresh())
    )
      res = await attempt(accessToken())
    return res
  }

  // Ends the session here, revokes the refresh token, and (by default)
  // signs out at the issuer, returning to postLogoutRedirectUri.
  async function signOut(opts: { redirect?: boolean } = {}): Promise<void> {
    const stored = await load()
    const rt = refreshToken ?? stored?.refreshToken
    const hint = idToken ?? stored?.idToken
    clear("signed_out")
    await save(null)
    const m = await metadata().catch(() => null)
    if (rt && m?.revocation_endpoint)
      await doFetch(m.revocation_endpoint, {
        method: "POST",
        headers: { "Content-Type": "application/x-www-form-urlencoded" },
        body: new URLSearchParams({
          token: rt,
          token_type_hint: "refresh_token",
          client_id: options.clientId,
        }).toString(),
      }).catch(() => undefined)
    bound = prefer
    await deleteDPoPKey(keyName)
    if ((opts.redirect ?? true) && m?.end_session_endpoint) {
      const url = new URL(m.end_session_endpoint)
      url.searchParams.set("client_id", options.clientId)
      if (hint) url.searchParams.set("id_token_hint", hint)
      if (options.postLogoutRedirectUri)
        url.searchParams.set(
          "post_logout_redirect_uri",
          new URL(options.postLogoutRedirectUri, location.href).toString()
        )
      location.assign(url.toString())
    }
  }

  return {
    subscribe(listener: () => void): () => void {
      listeners.add(listener)
      return () => listeners.delete(listener)
    },
    getSnapshot: (): AuthSession => session,
    getAccessToken: accessToken,
    getUser: (): IssuerUser | null =>
      session.status === "authenticated" ? user : null,
    start,
    stop,
    ready,
    refresh,
    signIn,
    // A fresh sign-in at the issuer, for an API that demands a recent one.
    stepUp: (opts: Omit<IssuerSignInOptions, "maxAge"> = {}) =>
      signIn({ ...opts, maxAge: 0 }),
    completeSignIn,
    authFetch,
    signOut,
  }
}
