import { toSignInResult } from "./authResult.ts"
import type { PendingSignIn, SignInResult } from "./authResult.ts"
import type { AuthErrorCode } from "./codes.ts"
import {
  AuthKitError,
  AuthSessionChangedError,
  errorMetadata,
  readAuthKitError,
} from "./errors.ts"
import { decodeAccessClaims, principalOf } from "./jwt.ts"
import type { AccessClaims } from "./jwt.ts"
import { randomNonce, waitForPopup } from "./popup.ts"
import { safeReturnTo } from "./returnTo.ts"
import type {
  Availability,
  BackupCodes,
  Capabilities,
  FreshAuth,
  ListPage,
  Membership,
  OIDCStart,
  PermissionSet,
  PublicUser,
  Session,
  SessionEvent,
  SignInKey,
  SolanaLinkedAccount,
  SolanaSignInOutput,
  TokenSet,
  TwoFactorFactor,
  TwoFactorFactorCreated,
  TwoFactorMethod,
  TwoFactorSetup,
  TwoFactorStatus,
  UserProfile,
  UserSecurity,
} from "./types.ts"
import { creationOptions, registrationBody } from "./webauthn.ts"

// Durable refresh-token home for mounts without the refresh cookie. Cookie
// mounts (the browser default) need none: the token never reaches script.
export type RefreshTokenStorage = {
  get(): string | null
  set(token: string | null): void
}

// A non-secret "this browser is signed in" note: it renders the signed-in
// shell before the cookie restore finishes and syncs tabs. It never holds a
// token; the refresh token stays in its HttpOnly cookie, the access token in
// memory.
export type SessionHint = {
  userId: string
  username?: string
  // Epoch ms after which the hint is ignored.
  expiresAt: number
}

export type SessionHintOptions = {
  // Default localStorage.
  storage?: Storage
  // Default "authkit:session:<baseUrl>".
  key?: string
  // How long a hint is trusted without a refresh. Default 30 days.
  ttlSeconds?: number
}

// An AuthKit route refused because the account has no proven address (403
// verification_required, reason contact_unproven).
export type ContactProofRequest = {
  identifier: string
  channel: string
}

// Resolves true once the address is proven; the refused request is then
// retried once.
export type ContactProofHandler = (
  request: ContactProofRequest
) => Promise<boolean>

export type AuthClientOptions = {
  // AuthKit JSON API mount. Default "/api/v1".
  baseUrl?: string
  // Browser OIDC mount (outside the API prefix). Default "/oidc".
  oidcBaseUrl?: string
  fetch?: typeof fetch
  storage?: RefreshTokenStorage
  // Sent as ?lang= (AuthKit's highest-priority language selector).
  language?: () => string | null | undefined
  // Refresh this long before access-token expiry. Default 300.
  refreshLeadSeconds?: number
  // Signed-in hint for instant restore and cross-tab sync; false disables.
  sessionHint?: SessionHintOptions | false
}

export type AuthSession =
  // hint: this browser was signed in; the cookie restore is under way.
  | { status: "loading"; hint?: SessionHint }
  | {
      status: "anonymous"
      reason: "initial" | "signed_out" | "expired"
      // A refresh that now needs another step (a second factor, enrollment).
      continuation: PendingSignIn | null
    }
  | {
      status: "authenticated"
      accessToken: string
      userId: string
      claims: AccessClaims
      // Epoch ms, from the JWT exp or expires_in.
      expiresAt: number | null
    }

// A browser OIDC redirect result, read from the page's fragment.
export type RedirectResult =
  | { kind: "sign_in"; result: SignInResult; provider?: string }
  | { kind: "linked"; provider?: string }
  | { kind: "error"; code: string; flow: string; provider?: string }

export type PopupResult =
  | { ok: true; result: SignInResult; provider?: string }
  | { ok: false; reason: "blocked" | "closed" | "timeout" | "session_changed" }
  | { ok: false; reason: "provider_error"; code: string; provider?: string }

export type RequestOptions = {
  body?: unknown
  query?: Record<string, string | number | boolean | null | undefined>
  signal?: AbortSignal
  // Override the session bearer (e.g. an enrollment token); null sends none.
  bearer?: string | null
}

// A factor enrollment's answer; auth is the sign-in it finished, if any.
export type TwoFactorEnrolled = Omit<TwoFactorFactorCreated, "auth"> & {
  auth: SignInResult | null
}

export type LinkFragment = {
  status: string
  channel: string
  token: string
  returnTo?: string
}

// 401 codes that mean "this bearer is stale", as opposed to a wrong password or code.
const STALE_BEARER = new Set<AuthErrorCode>([
  "token_expired",
  "invalid_token",
  "session_revoked",
  "unauthenticated",
  "unknown_kid",
])
const TERMINAL_REFRESH = new Set([400, 401, 403])
const MAX_TIMER = 2_147_483_647

type Listener = () => void
type Rec = Record<string, unknown>

const rec = (v: unknown): Rec =>
  v !== null && typeof v === "object" ? (v as Rec) : {}
const str = (v: unknown): string | undefined =>
  typeof v === "string" && v ? v : undefined

const trimSlash = (s: string) => s.replace(/\/+$/, "")
const segment = encodeURIComponent

export type AuthClient = ReturnType<typeof createAuthClient>

export function createAuthClient(options: AuthClientOptions = {}) {
  const baseUrl = trimSlash(options.baseUrl ?? "/api/v1")
  const oidcBaseUrl = trimSlash(options.oidcBaseUrl ?? "/oidc")
  const doFetch: typeof fetch = (...args) =>
    (options.fetch ?? globalThis.fetch)(...args)
  const storage = options.storage
  const leadMs = (options.refreshLeadSeconds ?? 300) * 1000

  // --- signed-in hint ---------------------------------------------------------

  const hintOptions =
    options.sessionHint === false ? null : (options.sessionHint ?? {})
  const hintKey = hintOptions?.key ?? `authkit:session:${baseUrl}`
  const hintTtlMs = (hintOptions?.ttlSeconds ?? 30 * 86_400) * 1000
  const hintStore = (): Storage | null => {
    if (!hintOptions) return null
    if (hintOptions.storage) return hintOptions.storage
    try {
      return typeof localStorage === "undefined" ? null : localStorage
    } catch {
      return null
    }
  }
  const readHint = (): SessionHint | null => {
    try {
      const raw = hintStore()?.getItem(hintKey)
      if (!raw) return null
      const h = rec(JSON.parse(raw))
      const userId = str(h.userId)
      const expiresAt = typeof h.expiresAt === "number" ? h.expiresAt : 0
      if (!userId || expiresAt <= Date.now()) return null
      return { userId, username: str(h.username), expiresAt }
    } catch {
      return null
    }
  }
  const writeHint = (hint: SessionHint | null) => {
    try {
      const store = hintStore()
      if (!store) return
      if (hint) store.setItem(hintKey, JSON.stringify(hint))
      else store.removeItem(hintKey)
    } catch {
      // storage unavailable (private mode, quota): the hint is optional
    }
  }

  let generation = 0
  const initialHint = readHint()
  let session: AuthSession = initialHint
    ? { status: "loading", hint: initialHint }
    : { status: "loading" }
  const listeners = new Set<Listener>()
  let refreshing: { generation: number; promise: Promise<boolean> } | null =
    null
  let notBefore = { generation: -1, at: 0 }
  let timer: ReturnType<typeof setTimeout> | null = null
  let retries = 0
  let started = false

  const emit = (next: AuthSession) => {
    session = next
    for (const listener of listeners) {
      try {
        listener()
      } catch {
        // one failing subscriber must not starve the rest
      }
    }
  }

  const accessToken = () =>
    session.status === "authenticated" ? session.accessToken : null

  const url = (base: string, path: string, query?: RequestOptions["query"]) => {
    const params = new URLSearchParams()
    for (const [k, v] of Object.entries(query ?? {})) {
      if (v !== undefined && v !== null && v !== "") params.set(k, String(v))
    }
    const lang = options.language?.()
    if (lang && !params.has("lang")) params.set("lang", lang)
    const qs = params.toString()
    return `${base}${path}${qs ? `?${qs}` : ""}`
  }

  // --- session state -------------------------------------------------------

  // mode "login" starts a new session; "refresh" continues the current one.
  const commit = (
    tokens: TokenSet,
    expected: number,
    mode: "login" | "refresh"
  ) => {
    if (expected !== generation) throw new AuthSessionChangedError()
    const claims = decodeAccessClaims(tokens.access_token) ?? {}
    const userId = principalOf(claims) ?? ""
    if (
      mode === "refresh" &&
      session.status === "authenticated" &&
      session.userId !== userId
    ) {
      throw new AuthSessionChangedError()
    }
    if (mode === "login") generation++
    if (tokens.refresh_token) storage?.set(tokens.refresh_token)
    const expiresAt =
      typeof claims.exp === "number"
        ? claims.exp * 1000
        : typeof tokens.expires_in === "number"
          ? Date.now() + tokens.expires_in * 1000
          : null
    retries = 0
    const prior = readHint()
    writeHint({
      userId,
      username:
        str(claims.username) ??
        (prior?.userId === userId ? prior.username : undefined),
      expiresAt: Date.now() + hintTtlMs,
    })
    emit({
      status: "authenticated",
      accessToken: tokens.access_token,
      userId,
      claims,
      expiresAt,
    })
    schedule()
  }

  // Records the signed-in user's display name in the hint (access tokens need
  // not carry it), so the next reload can show it before /me answers.
  const rememberUsername = (userId: string, username: string) => {
    const hint = readHint()
    if (hint?.userId !== userId || hint.username === username) return
    writeHint({ ...hint, username })
  }

  // keepHint: another tab already rewrote the hint.
  const clear = (
    reason: "initial" | "signed_out" | "expired",
    continuation: PendingSignIn | null = null,
    keepHint = false
  ) => {
    generation++
    storage?.set(null)
    if (!keepHint) writeHint(null)
    clearTimer()
    emit({ status: "anonymous", reason, continuation })
  }

  // --- refresh --------------------------------------------------------------

  const backoff = (gen: number, seconds?: number) => {
    notBefore = {
      generation: gen,
      at: Date.now() + Math.max(1000, (seconds ?? 5) * 1000),
    }
  }

  // The logout response clears the refresh cookie. Cookie-bearing requests
  // wait for it, or a sign-in answered first would have its cookie wiped.
  let signingOut: Promise<void> | null = null
  const cookieFetch: typeof fetch = async (...args) => {
    while (signingOut) await signingOut
    return doFetch(...args)
  }

  // The session ends: a refresh was refused, or now needs another step.
  const endRefresh = (
    current: AuthSession | null,
    continuation: PendingSignIn | null
  ) => {
    // Only a live session can expire; an anonymous cold boot just settles.
    if (current) return clear("expired", continuation)
    // A cold boot's hint was stale; a tab adopting another tab's sign-in
    // leaves the hint to that tab.
    if (session.status === "loading") writeHint(null)
    emit({
      status: "anonymous",
      reason: session.status === "anonymous" ? session.reason : "initial",
      continuation,
    })
  }

  const refreshOnce = async (gen: number): Promise<boolean> => {
    const current = session.status === "authenticated" ? session : null
    const body: Rec = { grant_type: "refresh_token" }
    const stored = storage?.get()
    if (stored) body.refresh_token = stored
    let res: Response
    try {
      res = await cookieFetch(url(baseUrl, "/token"), {
        method: "POST",
        credentials: "include",
        headers: {
          "Content-Type": "application/json",
          Accept: "application/json",
        },
        body: JSON.stringify(body),
      })
    } catch {
      if (gen === generation) backoff(gen)
      return false
    }
    if (gen !== generation) return false
    if (!res.ok) {
      const err = await readAuthKitError(res)
      if (gen !== generation) return false
      if (TERMINAL_REFRESH.has(res.status)) endRefresh(current, null)
      else backoff(gen, err.retryAfterSeconds)
      return false
    }
    let result: SignInResult
    try {
      result = toSignInResult(await res.json())
    } catch {
      return false
    }
    if (gen !== generation) return false
    if (result.status !== "complete") {
      endRefresh(current, result)
      return false
    }
    try {
      commit(result.token_set, gen, "refresh")
    } catch {
      return false
    }
    notBefore = { generation: -1, at: 0 }
    return true
  }

  // Single-flight per session generation; a refresh never outlives its session.
  const refresh = (): Promise<boolean> => {
    const gen = generation
    if (refreshing?.generation === gen) return refreshing.promise
    if (notBefore.generation === gen && Date.now() < notBefore.at)
      return Promise.resolve(false)
    const promise = refreshOnce(gen).finally(() => {
      if (refreshing?.promise === promise) refreshing = null
    })
    refreshing = { generation: gen, promise }
    return promise
  }

  // --- scheduler + visibility -----------------------------------------------

  function clearTimer() {
    if (timer) clearTimeout(timer)
    timer = null
  }

  const waitFor = (ms: number) => {
    clearTimer()
    timer = setTimeout(() => void tick(), Math.min(Math.max(0, ms), MAX_TIMER))
  }

  function schedule() {
    clearTimer()
    if (
      !started ||
      session.status !== "authenticated" ||
      session.expiresAt === null
    )
      return
    waitFor(session.expiresAt - leadMs - Date.now())
  }

  async function tick() {
    timer = null
    const gen = generation
    if (await refresh()) return
    if (!started || gen !== generation || session.status !== "authenticated")
      return
    const retryAfter =
      notBefore.generation === gen ? notBefore.at - Date.now() : 0
    waitFor(Math.max(retryAfter, Math.min(5000 * 2 ** retries++, 300_000)))
  }

  const onWake = () => {
    if (
      typeof document !== "undefined" &&
      document.visibilityState === "hidden"
    )
      return
    if (session.status !== "authenticated") return
    // Background tabs throttle timers; catch up if we are inside the lead window.
    if (session.expiresAt !== null && session.expiresAt - Date.now() < leadMs)
      void tick()
    else schedule()
  }

  // Another tab signed in, out, or as someone else: follow it. The refresh
  // cookie is shared, so adopting is a refresh; signing out needs no request
  // because the other tab already ended the session.
  const onStorage = (e: StorageEvent) => {
    if (e.key !== hintKey && e.key !== null) return
    if (session.status === "loading") return
    const hint = readHint()
    const current = session.status === "authenticated" ? session.userId : null
    if (hint?.userId === current) return
    if (current) clear("signed_out", null, true)
    if (hint) void refresh()
  }

  const restore = async () => {
    await refresh()
    if (session.status === "loading")
      emit({ status: "anonymous", reason: "initial", continuation: null })
  }

  const stop = () => {
    started = false
    clearTimer()
    if (typeof document !== "undefined")
      document.removeEventListener("visibilitychange", onWake)
    if (typeof window !== "undefined") {
      window.removeEventListener("online", onWake)
      window.removeEventListener("storage", onStorage)
    }
  }

  // Restores the session from the refresh credential, then keeps it fresh.
  const start = (): (() => void) => {
    if (!started) {
      started = true
      if (typeof document !== "undefined")
        document.addEventListener("visibilitychange", onWake)
      if (typeof window !== "undefined") {
        window.addEventListener("online", onWake)
        window.addEventListener("storage", onStorage)
      }
      if (session.status === "loading") void restore()
      else schedule()
    }
    return stop
  }

  // Resolves once a started client's restore has settled, so a request made
  // while the page loads carries the restored session instead of none.
  const ready = (): Promise<void> => {
    if (!started || session.status !== "loading") return Promise.resolve()
    return new Promise((resolve) => {
      const settled = () => {
        if (session.status === "loading") return
        listeners.delete(settled)
        resolve()
      }
      listeners.add(settled)
    })
  }

  // --- transport ------------------------------------------------------------

  let proveContact: ContactProofHandler | null = null
  // One handler at a time (the latest wins); returns its unregister.
  const onContactProofRequired = (handler: ContactProofHandler) => {
    proveContact = handler
    return () => {
      if (proveContact === handler) proveContact = null
    }
  }
  // True when res is a contact_unproven refusal the handler has now resolved.
  const contactProven = async (res: Response): Promise<boolean> => {
    const handler = proveContact
    if (res.status !== 403 || !handler) return false
    const err = await readAuthKitError(res.clone()).catch(() => null)
    const meta = errorMetadata(err, "verification_required")
    const identifier = str(meta?.identifier)
    if (meta?.reason !== "contact_unproven" || !identifier) return false
    return handler({ identifier, channel: str(meta.channel) ?? "email" })
  }

  const send = (
    method: string,
    target: string,
    opts: RequestOptions,
    bearer: string | null
  ) => {
    const headers: Record<string, string> = { Accept: "application/json" }
    if (opts.body !== undefined) headers["Content-Type"] = "application/json"
    if (bearer) headers.Authorization = `Bearer ${bearer}`
    return cookieFetch(target, {
      method,
      headers,
      body: opts.body === undefined ? undefined : JSON.stringify(opts.body),
      signal: opts.signal,
      credentials: "same-origin",
    })
  }

  // One AuthKit call. Throws AuthKitError; an empty body resolves undefined.
  async function request<T = unknown>(
    method: string,
    path: string,
    opts: RequestOptions = {}
  ): Promise<T> {
    return (await exchange(method, path, opts)).body as T
  }

  async function exchange(
    method: string,
    path: string,
    opts: RequestOptions
  ): Promise<{ status: number; body: unknown }> {
    const target = url(baseUrl, path, opts.query)
    const explicit = opts.bearer !== undefined
    if (!explicit) await ready()
    const bearer = explicit ? (opts.bearer ?? null) : accessToken()
    let res = await send(method, target, opts, bearer)
    if (res.status === 401 && !explicit && bearer) {
      const err = await readAuthKitError(res.clone())
      if (STALE_BEARER.has(err.code as AuthErrorCode) && (await refresh())) {
        const next = accessToken()
        if (next && next !== bearer)
          res = await send(method, target, opts, next)
      }
    }
    // Proving the address may rotate the session: retry with the new bearer.
    if (await contactProven(res))
      res = await send(method, target, opts, explicit ? bearer : accessToken())
    if (!res.ok) throw await readAuthKitError(res)
    const text = res.status === 204 ? "" : await res.text()
    return { status: res.status, body: text ? JSON.parse(text) : undefined }
  }

  // fetch for host APIs: attaches the session bearer and retries once after a
  // refresh on 401. Never throws on HTTP status.
  async function authFetch(
    input: RequestInfo | URL,
    init: RequestInit = {}
  ): Promise<Response> {
    const original = input instanceof Request ? input.clone() : input
    const attempt = (token: string | null, source: RequestInfo | URL) => {
      const headers = new Headers(
        init.headers ?? (source instanceof Request ? source.headers : undefined)
      )
      if (token) headers.set("Authorization", `Bearer ${token}`)
      return doFetch(source, { ...init, headers })
    }
    await ready()
    const bearer = accessToken()
    let res = await attempt(bearer, input)
    if (res.status === 401 && bearer && (await refresh())) {
      const next = accessToken()
      if (next && next !== bearer) res = await attempt(next, original)
    }
    // A Request body is consumed; only plain inputs are retried.
    if (!(input instanceof Request) && (await contactProven(res)))
      res = await attempt(accessToken(), input)
    return res
  }

  // --- generation-guarded flows ----------------------------------------------

  // Runs a sign-in call and commits the session a complete AuthResult
  // carries. Every other status is returned for the caller's next step.
  async function completeSignIn(
    call: () => Promise<unknown>
  ): Promise<SignInResult> {
    const gen = generation
    return signedIn(await call(), gen)
  }

  function signedIn(body: unknown, gen: number): SignInResult {
    const result = toSignInResult(body)
    if (result.status !== "complete") {
      if (gen !== generation) throw new AuthSessionChangedError()
      return result
    }
    commit(result.token_set, gen, "login")
    if (result.user) rememberUsername(result.user.id, result.user.username)
    return result
  }

  // Adopts the fresh token a same-session re-authentication answers with
  // (step-up, password change, factor enrollment).
  async function sameSession(
    call: () => Promise<unknown>
  ): Promise<SignInResult | null> {
    const gen = generation
    const body = await call()
    if (body === undefined) return null
    const result = toSignInResult(body)
    if (result.status === "complete") commit(result.token_set, gen, "refresh")
    return result
  }

  const signOut = async (): Promise<void> => {
    const bearer = accessToken()
    clear("signed_out")
    if (!bearer) return
    const done = doFetch(url(baseUrl, "/logout"), {
      method: "DELETE",
      credentials: "include",
      headers: { Authorization: `Bearer ${bearer}` },
    }).then(
      () => undefined,
      () => undefined // local sign-out already happened
    )
    signingOut = done
    await done
    if (signingOut === done) signingOut = null
  }

  // --- OIDC ------------------------------------------------------------------

  // A GET navigation that starts a provider sign-in (no invitation: that is
  // bound by oidcLoginStart, never put in a URL).
  const oidcLoginUrl = (
    provider: string,
    opts: { returnTo?: string; popupNonce?: string } = {}
  ) =>
    url(oidcBaseUrl, `/${segment(provider)}/login`, {
      return_to: safeReturnTo(opts.returnTo),
      ui: opts.popupNonce ? "popup" : undefined,
      popup_nonce: opts.popupNonce,
    })

  // Starts a provider sign-in by POST, binding the invitation to the flow's
  // server-side state, and resolves the provider URL to navigate to. The
  // answer sets the flow's state cookie, so it is credentialed.
  async function oidcLoginStart(
    provider: string,
    opts: { returnTo?: string; inviteCode?: string; popupNonce?: string } = {}
  ): Promise<string> {
    const res = await cookieFetch(
      url(baseUrl, `/oidc/${segment(provider)}/login/start`),
      {
        method: "POST",
        credentials: "include",
        headers: {
          "Content-Type": "application/json",
          Accept: "application/json",
        },
        body: JSON.stringify({
          return_to: safeReturnTo(opts.returnTo) ?? undefined,
          invite_code: opts.inviteCode,
          ui: opts.popupNonce ? "popup" : undefined,
          popup_nonce: opts.popupNonce,
        }),
      }
    )
    if (!res.ok) throw await readAuthKitError(res)
    const start = (await res.json()) as Partial<OIDCStart>
    if (!start.auth_url) throw new Error("AuthKit returned no auth_url")
    return start.auth_url
  }

  // Trades a browser OIDC result's one-time code for its AuthResult.
  const exchangeCode = (code: string) =>
    request<unknown>("POST", "/oidc/exchange", { body: { code }, bearer: null })

  // Full-page provider sign-in; the result lands on the OIDC return path
  // (completeRedirect).
  async function signInWithRedirect(
    provider: string,
    opts: { returnTo?: string; inviteCode?: string } = {}
  ): Promise<void> {
    window.location.assign(
      opts.inviteCode
        ? await oidcLoginStart(provider, opts)
        : oidcLoginUrl(provider, opts)
    )
  }

  // Must be called from a user gesture: the window opens synchronously.
  async function signInWithPopup(
    provider: string,
    opts: { returnTo?: string; inviteCode?: string; timeoutMs?: number } = {}
  ): Promise<PopupResult> {
    const gen = generation
    const nonce = randomNonce()
    const allowedOrigins = new Set([
      window.location.origin,
      new URL(oidcBaseUrl, window.location.href).origin,
    ])
    const target = opts.inviteCode
      ? () => oidcLoginStart(provider, { ...opts, popupNonce: nonce })
      : oidcLoginUrl(provider, { returnTo: opts.returnTo, popupNonce: nonce })
    const waited = await waitForPopup(target, {
      nonce,
      allowedOrigins,
      timeoutMs: opts.timeoutMs ?? 300_000,
    })
    if (!waited.ok) {
      if (waited.reason !== "start_failed") return waited
      const { error } = waited
      const code = error instanceof AuthKitError ? error.code : undefined
      return {
        ok: false,
        reason: "provider_error",
        code: code ?? "oidc_begin_failed",
      }
    }
    const msg = waited.message
    const from = str(msg.provider)
    if (gen !== generation) return { ok: false, reason: "session_changed" }
    const code = str(msg.code)
    if (!code)
      return {
        ok: false,
        reason: "provider_error",
        code: str(msg.error) ?? "unknown_error",
        provider: from,
      }
    try {
      const result = await completeSignIn(() => exchangeCode(code))
      return { ok: true, result, provider: from }
    } catch (err) {
      if (err instanceof AuthSessionChangedError)
        return { ok: false, reason: "session_changed" }
      if (err instanceof AuthKitError)
        return {
          ok: false,
          reason: "provider_error",
          code: err.code,
          provider: from,
        }
      throw err
    }
  }

  // Reads (and, without an argument, scrubs) the page fragment when pick
  // accepts it.
  const takeFragment = (
    hash: string | undefined,
    pick: (params: URLSearchParams) => boolean
  ): URLSearchParams | null => {
    const own = hash === undefined
    const raw = own ? (globalThis.location?.hash ?? "") : hash
    const params = new URLSearchParams(raw.replace(/^#/, ""))
    if (!pick(params)) return null
    if (own && typeof history !== "undefined")
      history.replaceState(
        history.state,
        "",
        `${location.pathname}${location.search}`
      )
    return params
  }

  // A sign-in or link result carries state (or the flow); a step-up
  // return carries neither.
  const isLoginFragment = (p: URLSearchParams) =>
    (p.get("flow") === "link" && p.get("result") === "success") ||
    ((p.has("code") || p.has("error")) && (p.has("state") || p.has("flow")))
  const isStepUpFragment = (p: URLSearchParams) =>
    (p.has("code") || p.has("error")) && !p.has("state") && !p.has("flow")

  // Finishes a provider sign-in or link on the OIDC return path: trades the
  // fragment's one-time code for the AuthResult. Null when the fragment holds
  // none. Without an argument it reads and scrubs window.location.hash.
  async function completeRedirect(
    hash?: string
  ): Promise<RedirectResult | null> {
    const params = takeFragment(hash, isLoginFragment)
    if (!params) return null
    const provider = params.get("provider") ?? undefined
    if (params.get("result") === "success") return { kind: "linked", provider }
    const code = params.get("code")
    if (!code)
      return {
        kind: "error",
        code: params.get("error") ?? "unknown_error",
        flow: params.get("flow") ?? "login",
        provider,
      }
    return {
      kind: "sign_in",
      result: await completeSignIn(() => exchangeCode(code)),
      provider,
    }
  }

  // Finishes an OIDC step-up on its return page (`#code=` or `#error=`):
  // adopts the re-authenticated session. Null when the fragment holds none;
  // throws AuthKitError when the step-up failed.
  async function completeStepUp(hash?: string): Promise<FreshAuth | null> {
    const params = takeFragment(hash, isStepUpFragment)
    if (!params) return null
    const code = params.get("code")
    if (!code) {
      const failed = params.get("error") ?? "unknown_error"
      throw new AuthKitError(0, { type: "", code: failed, message: failed })
    }
    const gen = generation
    const result = toSignInResult(await exchangeCode(code))
    if (result.status !== "complete")
      throw new Error("AuthKit returned no step-up session")
    commit(
      result.token_set,
      gen,
      session.status === "authenticated" ? "refresh" : "login"
    )
    return result.fresh_auth
  }

  // Same-session re-authentication's freshness.
  const freshAuth = (result: SignInResult | null): FreshAuth => {
    if (!result?.fresh_auth) throw new Error("AuthKit returned no fresh_auth")
    return result.fresh_auth
  }

  // --- AuthKit routes ----------------------------------------------------------

  const api = {
    getCapabilities: (signal?: AbortSignal) =>
      request<Capabilities>("GET", "/capabilities", { signal, bearer: null }),

    signInWithPassword: (input: { identifier: string; password: string }) =>
      completeSignIn(() =>
        request("POST", "/password/login", { body: input, bearer: null })
      ),

    // Null: a code went to the identifier (202); confirmVerification
    // finishes the registration.
    register: async (input: {
      identifier: string
      username: string
      password: string
      inviteCode?: string
    }): Promise<SignInResult | null> => {
      const gen = generation
      const { status, body } = await exchange("POST", "/register", {
        bearer: null,
        body: {
          identifier: input.identifier,
          username: input.username,
          password: input.password,
          invite_code: input.inviteCode,
        },
      })
      return status === 200 ? signedIn(body, gen) : null
    },

    checkAvailability: (
      input: { username?: string; email?: string; phoneNumber?: string },
      signal?: AbortSignal
    ) =>
      request<Availability>("GET", "/register/availability", {
        signal,
        bearer: null,
        query: {
          username: input.username,
          email: input.email,
          phone_number: input.phoneNumber,
        },
      }),

    // Always 204: a wrong password leaves the pending registration in place.
    abandonRegistration: (input: { identifier: string; password: string }) =>
      request<void>("POST", "/register/abandon", { body: input, bearer: null }),

    // Sends a code (or link) proving an address; never changes a contact.
    requestVerification: (input: { identifier: string }) =>
      request<void>("POST", "/verify/request", {
        body: { identifier: input.identifier },
        bearer: null,
      }),

    // Null (204): a signed-in proof, the session unchanged. Otherwise the
    // sign-in the proof finished (or its next step).
    confirmVerification: async (
      input:
        | { identifier: string; code: string }
        | { token: string; identifier?: string }
    ): Promise<SignInResult | null> => {
      const gen = generation
      const { status, body } = await exchange("POST", "/verify/confirm", {
        body: input,
      })
      return status === 204 ? null : signedIn(body, gen)
    },

    // Sends a code to the new address; confirmVerification switches it.
    changeEmail: (email: string) =>
      request<void>("PUT", "/me/email", { body: { email } }),

    changePhone: (phoneNumber: string) =>
      request<void>("PUT", "/me/phone", {
        body: { phone_number: phoneNumber },
      }),

    removePhone: () => request<void>("DELETE", "/me/phone"),

    requestPasswordReset: (identifier: string) =>
      request<void>("POST", "/password/reset/request", {
        body: { identifier },
        bearer: null,
      }),

    confirmPasswordReset: (input: { token: string; newPassword: string }) =>
      request<void>("POST", "/password/reset/confirm", {
        body: { token: input.token, new_password: input.newPassword },
        bearer: null,
      }),

    // A current password re-authenticates the session on the way.
    changePassword: (input: {
      currentPassword?: string
      newPassword: string
    }) =>
      sameSession(() =>
        request<unknown>("PUT", "/me/password", {
          body: {
            current_password: input.currentPassword ?? "",
            new_password: input.newPassword,
          },
        })
      ).then(() => undefined),

    verifyTwoFactor: (input: {
      userId: string
      challenge: string
      code: string
      factorId?: string
      backupCode?: boolean
    }) =>
      completeSignIn(() =>
        request("POST", "/2fa/verify", {
          bearer: null,
          body: {
            user_id: input.userId,
            challenge: input.challenge,
            code: input.code,
            factor_id: input.factorId,
            backup_code: input.backupCode,
          },
        })
      ),

    // Resends the pending sign-in's code, or switches it to another factor.
    sendTwoFactorChallenge: async (input: {
      userId: string
      challenge: string
      factorId?: string
    }) => {
      const result = await completeSignIn(() =>
        request("POST", "/2fa/challenge", {
          bearer: null,
          body: {
            user_id: input.userId,
            challenge: input.challenge,
            factor_id: input.factorId,
          },
        })
      )
      if (result.status !== "second_factor_required")
        throw new Error("AuthKit returned no second-factor step")
      return result
    },

    getTwoFactor: (signal?: AbortSignal) =>
      request<TwoFactorStatus>("GET", "/me/2fa", { signal }),

    // Starts a factor: TOTP answers its secret, email and SMS send a code.
    // An enrollment token (AuthResult enrollment_required) finishes a forced
    // enrollment.
    setupTwoFactor: (
      input: { method: TwoFactorMethod; phoneNumber?: string },
      opts: { enrollmentToken?: TokenSet } = {}
    ) =>
      request<TwoFactorSetup>("POST", "/me/2fa/setup", {
        bearer: opts.enrollmentToken?.access_token,
        body: { method: input.method, phone_number: input.phoneNumber },
      }),

    // Confirms a started factor. Its auth, adopted here, is the session the
    // enrollment finished (enrollment token) or re-verified.
    addTwoFactorFactor: async (
      input: {
        method: TwoFactorMethod
        code: string
        phoneNumber?: string
        makeDefault?: boolean
      },
      opts: { enrollmentToken?: TokenSet } = {}
    ): Promise<TwoFactorEnrolled> => {
      const gen = generation
      const created = await request<TwoFactorFactorCreated>(
        "POST",
        "/me/2fa/factors",
        {
          bearer: opts.enrollmentToken?.access_token,
          body: {
            method: input.method,
            code: input.code,
            phone_number: input.phoneNumber,
            default: input.makeDefault,
          },
        }
      )
      const auth = created.auth ? toSignInResult(created.auth) : null
      if (auth?.status === "complete") {
        commit(auth.token_set, gen, opts.enrollmentToken ? "login" : "refresh")
      } else if (auth && gen !== generation) {
        throw new AuthSessionChangedError()
      }
      return { ...created, auth }
    },

    setDefaultTwoFactorFactor: (factorId: string) =>
      request<TwoFactorFactor>(
        "PATCH",
        `/me/2fa/factors/${segment(factorId)}`,
        {
          body: { default: true },
        }
      ),

    removeTwoFactorFactor: (factorId: string) =>
      request<void>("DELETE", `/me/2fa/factors/${segment(factorId)}`),

    // Removes every factor and backup code.
    disableTwoFactor: () => request<void>("DELETE", "/me/2fa"),

    regenerateBackupCodes: () =>
      request<BackupCodes>("POST", "/me/2fa/backup-codes").then(
        (r) => r.backup_codes
      ),

    // Freshness, MFA state and the step-up methods on offer.
    getSecurity: (signal?: AbortSignal) =>
      request<UserSecurity>("GET", "/me/security", { signal }),

    stepUpWithPassword: (password: string) =>
      sameSession(() =>
        request("POST", "/me/step-up/password", { body: { password } })
      ).then(freshAuth),

    // Sends an email or SMS step-up code (TOTP needs none).
    sendStepUpCode: (input: { method?: string } = {}) =>
      request<void>("POST", "/me/step-up/2fa/send", {
        body: { method: input.method },
      }),

    stepUpWithTwoFactor: (input: {
      code: string
      method?: string
      backupCode?: boolean
    }) =>
      sameSession(() =>
        request("POST", "/me/step-up/2fa", {
          body: {
            code: input.code,
            method: input.method,
            backup_code: input.backupCode,
          },
        })
      ).then(freshAuth),

    // The provider URL; AuthKit returns to returnTo#code= (completeStepUp).
    startOidcStepUp: (provider: string, returnTo: string) =>
      request<OIDCStart>("POST", `/oidc/${segment(provider)}/step-up/start`, {
        body: { return_to: safeReturnTo(returnTo) ?? "/" },
      }).then((r) => r.auth_url),

    // The provider URL; completion lands as #flow=link&result=success.
    startProviderLink: (provider: string) =>
      request<OIDCStart>("POST", `/oidc/${segment(provider)}/link/start`, {
        body: {},
      }).then((r) => r.auth_url),

    unlinkProvider: (provider: string) =>
      request<void>("DELETE", `/me/providers/${segment(provider)}`),

    listSessions: (signal?: AbortSignal) =>
      request<ListPage<Session>>("GET", "/me/sessions", { signal }).then(
        (r) => r.data
      ),

    revokeSessions: async (sessionIds: readonly string[]) => {
      await Promise.all(
        sessionIds.map((id) =>
          request<void>("DELETE", `/me/sessions/${segment(id)}`)
        )
      )
    },

    // Every session but this one.
    revokeOtherSessions: () => request<void>("DELETE", "/me/sessions"),

    listSessionEvents: (
      input: { kind?: string[]; cursor?: string; limit?: number } = {},
      signal?: AbortSignal
    ) =>
      request<ListPage<SessionEvent>>("GET", "/me/session-events", {
        signal,
        query: {
          kind: input.kind?.join(","),
          cursor: input.cursor,
          limit: input.limit,
        },
      }),

    // Passkeys and device keys.
    listSignInKeys: (signal?: AbortSignal) =>
      request<ListPage<SignInKey>>("GET", "/me/sign-in-keys", {
        signal,
      }).then((r) => r.data),

    renameSignInKey: (id: string, label: string) =>
      request<SignInKey>("PATCH", `/me/sign-in-keys/${segment(id)}`, {
        body: { label },
      }),

    revokeSignInKey: (id: string) =>
      request<void>("DELETE", `/me/sign-in-keys/${segment(id)}`),

    // Creates a passkey with the browser's authenticator (call from a click).
    registerPasskey: async (): Promise<SignInKey> => {
      const options = await request<unknown>(
        "POST",
        "/me/passkeys/register/begin"
      )
      const credential = await navigator.credentials.create({
        publicKey: creationOptions(options),
      })
      if (!(credential instanceof PublicKeyCredential))
        throw new Error("the browser created no passkey")
      return request<SignInKey>("POST", "/me/passkeys/register/finish", {
        body: registrationBody(credential),
      })
    },

    // null when the session changed while the profile was in flight.
    getMe: async (signal?: AbortSignal): Promise<UserProfile | null> => {
      const gen = generation
      const profile = await request<UserProfile>("GET", "/me", { signal })
      if (
        gen !== generation ||
        session.status !== "authenticated" ||
        profile.id !== session.userId
      )
        return null
      return profile
    },

    updateProfile: async (input: {
      username?: string
      preferredLanguage?: string
      avatarUrl?: string | null
    }) => {
      const profile = await request<UserProfile>("PATCH", "/me", {
        body: {
          username: input.username,
          preferred_language: input.preferredLanguage,
          avatar_url: input.avatarUrl,
        },
      })
      rememberUsername(profile.id, profile.username)
      return profile
    },

    // The caller's role and concrete permissions in one group; the root
    // group by default.
    getPermissions: (input: { groupId?: string } = {}, signal?: AbortSignal) =>
      request<PermissionSet>("GET", "/me/permissions", {
        signal,
        query: { group_id: input.groupId },
      }),

    // Public profiles, signed in or not: in request order, at most 100;
    // unknown ids are absent and deleted accounts are tombstones.
    getUsers: async (
      ids: readonly string[],
      signal?: AbortSignal
    ): Promise<PublicUser[]> =>
      ids.length === 0
        ? []
        : (
            await request<ListPage<PublicUser>>("GET", "/users", {
              signal,
              bearer: null,
              query: { ids: ids.join(",") },
            })
          ).data,

    // A public profile by username or a former one; null when nobody holds it.
    getUserByUsername: async (
      username: string,
      signal?: AbortSignal
    ): Promise<PublicUser | null> =>
      (
        await request<ListPage<PublicUser>>("GET", "/users", {
          signal,
          bearer: null,
          query: { username },
        })
      ).data[0] ?? null,

    redeemInvitation: (code: string) =>
      request<Membership>("POST", "/invitations/redeem", { body: { code } }),

    // Needs a recent sign-in (step_up_required otherwise); the session ends.
    deleteAccount: async () => {
      await request<void>("DELETE", "/me")
      clear("signed_out")
    },

    // Restores a soft-deleted account; the user then signs in normally.
    confirmAccountRecovery: (token: string) =>
      request<void>("POST", "/account/recovery/confirm", {
        body: { token },
        bearer: null,
      }),

    startPasswordless: (input: {
      identifier: string
      mode?: string
      returnTo?: string
      preferredLanguage?: string
      inviteCode?: string
    }) =>
      request<void>("POST", "/passwordless/start", {
        bearer: null,
        body: {
          identifier: input.identifier,
          mode: input.mode,
          return_to: safeReturnTo(input.returnTo) ?? undefined,
          preferred_language: input.preferredLanguage,
          invite_code: input.inviteCode,
        },
      }),

    confirmPasswordless: (
      input:
        | { identifier: string; code: string }
        | { token: string; identifier?: string }
    ) =>
      completeSignIn(() =>
        request("POST", "/passwordless/confirm", { body: input, bearer: null })
      ),

    // Links a Solana wallet from its signed SIWS output.
    linkSolanaWallet: (output: SolanaSignInOutput) =>
      request<SolanaLinkedAccount>("PUT", "/me/solana-wallet", {
        body: { output },
      }),
  }

  return {
    ...api,
    subscribe(listener: Listener): () => void {
      listeners.add(listener)
      return () => listeners.delete(listener)
    },
    getSnapshot: (): AuthSession => session,
    getAccessToken: accessToken,
    start,
    stop,
    refresh,
    signOut,
    request,
    authFetch,
    ready,
    rememberUsername,
    onContactProofRequired,
    completeSignIn,
    oidcLoginUrl,
    oidcLoginStart,
    signInWithRedirect,
    signInWithPopup,
    completeRedirect,
    completeStepUp,
  }
}

// #status=ready&channel=…&token=… on verification, reset and passwordless links.
export function readLinkFragment(hash: string): LinkFragment | null {
  const params = new URLSearchParams(hash.replace(/^#/, ""))
  const token = params.get("token")
  if (!token) return null
  return {
    status: params.get("status") ?? "",
    channel: params.get("channel") ?? "",
    token,
    returnTo: safeReturnTo(params.get("return_to")) ?? undefined,
  }
}
