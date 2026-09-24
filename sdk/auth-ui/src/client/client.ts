import {
  continuationFrom,
  continuationFromParams,
  readContinuation,
} from "./continuation.ts"
import type { AuthErrorCode } from "./codes.ts"
import type { LoginContinuation } from "./continuation.ts"
import {
  AuthKitError,
  AuthSessionChangedError,
  readAuthKitError,
} from "./errors.ts"
import { decodeAccessClaims, principalOf } from "./jwt.ts"
import type { AccessClaims } from "./jwt.ts"
import { randomNonce, waitForPopup } from "./popup.ts"
import { safeReturnTo } from "./returnTo.ts"
import type {
  Availability,
  Capabilities,
  FreshAuth,
  ListPage,
  NamingState,
  PermissionSet,
  Registration,
  RemovedMfaRole,
  TokenSet,
  TwoFactorMethod,
  TwoFactorStatus,
  UserProfile,
  UserSession,
} from "./types.ts"

// Durable refresh-token home for mounts without the refresh cookie. Cookie
// mounts (the browser default) need none: the token never reaches script.
export type RefreshTokenStorage = {
  get(): string | null
  set(token: string | null): void
}

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
}

export type AuthSession =
  | { status: "loading" }
  | {
      status: "anonymous"
      reason: "initial" | "signed_out" | "expired"
      // A refresh that now needs a second factor or enrollment.
      continuation: LoginContinuation | null
    }
  | {
      status: "authenticated"
      accessToken: string
      userId: string
      claims: AccessClaims
      // Epoch ms, from the JWT exp or expires_in.
      expiresAt: number | null
    }

export type AuthOutcome =
  { kind: "session"; returnTo?: string } | LoginContinuation

export type RedirectResult =
  | { kind: "session"; provider?: string; returnTo?: string }
  | { kind: "linked"; provider?: string }
  | { kind: "error"; code: string; flow: string; provider?: string }
  | LoginContinuation

export type PopupResult =
  | { ok: true; outcome: AuthOutcome; provider?: string }
  | { ok: false; reason: "blocked" | "closed" | "timeout" | "session_changed" }
  | { ok: false; reason: "provider_error"; code: string; provider?: string }

export type RequestOptions = {
  body?: unknown
  query?: Record<string, string | number | boolean | null | undefined>
  signal?: AbortSignal
  // Override the session bearer (e.g. an enrollment token); null sends none.
  bearer?: string | null
}

export type TwoFactorEnrollResult =
  | { kind: "default_set" }
  | { kind: "code_sent" }
  | { kind: "totp_started"; secret: string; otpauthUri: string }
  | {
      kind: "enabled"
      method: string
      backupCodes: string[]
      // AuthKit returned a session token: the enrolling session is (still)
      // signed in and now 2FA-verified.
      signedIn: boolean
      freshAuth?: FreshAuth
    }
  | LoginContinuation

export type TwoFactorStepUpResult =
  | { kind: "code_sent"; method: string; verificationId: string }
  | { kind: "stepped_up"; freshAuth: FreshAuth }

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
  "missing_token",
  "unauthorized",
  "unauthenticated",
  "not_authenticated",
  "authentication_required",
  "unknown_kid",
  "token_revoked",
])
const TERMINAL_REFRESH = new Set([400, 401, 403])
const MAX_TIMER = 2_147_483_647

type Listener = () => void
type Rec = Record<string, unknown>

const rec = (v: unknown): Rec =>
  v !== null && typeof v === "object" ? (v as Rec) : {}
const str = (v: unknown): string | undefined =>
  typeof v === "string" && v ? v : undefined

function tokenSetIn(body: unknown): TokenSet | null {
  const b = rec(body)
  const t = b.access_token ? b : rec(b.token_set)
  const access = str(t.access_token)
  if (!access) return null
  return {
    access_token: access,
    token_type: str(t.token_type) ?? "Bearer",
    expires_in: typeof t.expires_in === "number" ? t.expires_in : undefined,
    refresh_token: str(t.refresh_token),
  }
}

const trimSlash = (s: string) => s.replace(/\/+$/, "")

export type AuthClient = ReturnType<typeof createAuthClient>

export function createAuthClient(options: AuthClientOptions = {}) {
  const baseUrl = trimSlash(options.baseUrl ?? "/api/v1")
  const oidcBaseUrl = trimSlash(options.oidcBaseUrl ?? "/oidc")
  const doFetch: typeof fetch = (...args) =>
    (options.fetch ?? globalThis.fetch)(...args)
  const storage = options.storage
  const leadMs = (options.refreshLeadSeconds ?? 300) * 1000

  let generation = 0
  let session: AuthSession = { status: "loading" }
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
        : tokens.expires_in !== undefined
          ? Date.now() + tokens.expires_in * 1000
          : null
    retries = 0
    emit({
      status: "authenticated",
      accessToken: tokens.access_token,
      userId,
      claims,
      expiresAt,
    })
    schedule()
  }

  const clear = (
    reason: "initial" | "signed_out" | "expired",
    continuation: LoginContinuation | null = null
  ) => {
    generation++
    storage?.set(null)
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
      if (TERMINAL_REFRESH.has(res.status)) {
        const continuation = continuationFrom(err.code, err.metadata)
        // Only a live session can expire; an anonymous cold boot just settles.
        if (current) clear("expired", continuation)
        else
          emit({
            status: "anonymous",
            reason: session.status === "anonymous" ? session.reason : "initial",
            continuation,
          })
      } else {
        backoff(gen, err.retryAfterSeconds)
      }
      return false
    }
    let data: unknown
    try {
      data = await res.json()
    } catch {
      return false
    }
    if (gen !== generation) return false
    const tokens = tokenSetIn(data)
    if (!tokens) return false
    try {
      commit(tokens, gen, "refresh")
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
    if (typeof window !== "undefined")
      window.removeEventListener("online", onWake)
  }

  // Restores the session from the refresh credential, then keeps it fresh.
  const start = (): (() => void) => {
    if (!started) {
      started = true
      if (typeof document !== "undefined")
        document.addEventListener("visibilitychange", onWake)
      if (typeof window !== "undefined")
        window.addEventListener("online", onWake)
      if (session.status === "loading") void restore()
      else schedule()
    }
    return stop
  }

  // --- transport ------------------------------------------------------------

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
    const bearer = accessToken()
    const res = await attempt(bearer, input)
    if (res.status !== 401 || !bearer || !(await refresh())) return res
    const next = accessToken()
    return next && next !== bearer ? attempt(next, original) : res
  }

  // --- generation-guarded flows ----------------------------------------------

  // Runs a first-factor call and commits the session it yields. Continuations
  // (2FA, enrollment, recovery, verification) are returned, not thrown.
  async function completeSignIn(
    call: () => Promise<unknown>
  ): Promise<AuthOutcome> {
    const gen = generation
    let body: unknown
    try {
      body = await call()
    } catch (err) {
      const continuation = readContinuation(err)
      if (!continuation) throw err
      if (gen !== generation) throw new AuthSessionChangedError()
      return continuation
    }
    const tokens = tokenSetIn(body)
    if (!tokens) throw new Error("AuthKit returned no session")
    commit(tokens, gen, "login")
    return { kind: "session", returnTo: str(rec(body).return_to) }
  }

  // Adopts a fresh token set returned beside a same-session mutation (step-up).
  async function sameSession<T>(call: () => Promise<T>): Promise<T> {
    const gen = generation
    const body = await call()
    const tokens = tokenSetIn(body)
    if (tokens) commit(tokens, gen, "refresh")
    return body
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

  const oidcLoginUrl = (
    provider: string,
    opts: {
      returnTo?: string
      accountInviteToken?: string
      popupNonce?: string
    } = {}
  ) =>
    url(oidcBaseUrl, `/${encodeURIComponent(provider)}/login`, {
      return_to: safeReturnTo(opts.returnTo),
      account_invite_token: opts.accountInviteToken,
      ui: opts.popupNonce ? "popup" : undefined,
      popup_nonce: opts.popupNonce,
    })

  // Must be called from a user gesture: the window opens synchronously.
  async function signInWithPopup(
    provider: string,
    opts: {
      returnTo?: string
      accountInviteToken?: string
      timeoutMs?: number
    } = {}
  ): Promise<PopupResult> {
    const gen = generation
    const nonce = randomNonce()
    const allowedOrigins = new Set([
      window.location.origin,
      new URL(oidcBaseUrl, window.location.href).origin,
    ])
    const waited = await waitForPopup(
      oidcLoginUrl(provider, { ...opts, popupNonce: nonce }),
      {
        nonce,
        allowedOrigins,
        timeoutMs: opts.timeoutMs ?? 300_000,
      }
    )
    if (!waited.ok) return waited
    const msg = waited.message
    const from = str(msg.provider)
    if (gen !== generation) return { ok: false, reason: "session_changed" }
    if (msg.type === "AUTHKIT_OIDC_ERROR") {
      const code = str(msg.error) ?? "unknown_error"
      const continuation = continuationFrom(code, msg)
      return continuation
        ? { ok: true, outcome: continuation, provider: from }
        : { ok: false, reason: "provider_error", code, provider: from }
    }
    const tokens = tokenSetIn(msg)
    if (!tokens)
      return {
        ok: false,
        reason: "provider_error",
        code: "missing_token",
        provider: from,
      }
    commit(tokens, gen, "login")
    return {
      ok: true,
      outcome: {
        kind: "session",
        returnTo: safeReturnTo(opts.returnTo) ?? undefined,
      },
      provider: from,
    }
  }

  // Consumes AuthKit's redirect fragment (#access_token=… / #error=… / link result).
  // Without an argument it reads and scrubs window.location.hash.
  function completeRedirect(hash?: string): RedirectResult | null {
    const own = hash === undefined
    const raw = own ? (globalThis.location?.hash ?? "") : hash
    const params = new URLSearchParams(raw.replace(/^#/, ""))
    const provider = params.get("provider") ?? undefined
    let result: RedirectResult | null = null
    if (params.get("access_token")) {
      const expires = Number(params.get("expires_in"))
      commit(
        {
          access_token: params.get("access_token") ?? "",
          expires_in:
            Number.isFinite(expires) && params.get("expires_in")
              ? expires
              : undefined,
          refresh_token: params.get("refresh_token") ?? undefined,
        },
        generation,
        "login"
      )
      result = {
        kind: "session",
        provider,
        returnTo: safeReturnTo(params.get("return_to")) ?? undefined,
      }
    } else if (
      params.get("flow") === "link" &&
      params.get("result") === "success"
    ) {
      result = { kind: "linked", provider }
    } else if (params.get("error")) {
      const code = params.get("error") ?? ""
      const flow = params.get("flow") ?? "login"
      result = (flow === "login" && continuationFromParams(params)) || {
        kind: "error",
        code,
        flow,
        provider,
      }
    }
    if (own && result && typeof history !== "undefined") {
      history.replaceState(
        history.state,
        "",
        `${location.pathname}${location.search}`
      )
    }
    return result
  }

  // --- AuthKit routes ----------------------------------------------------------

  const api = {
    getCapabilities: (signal?: AbortSignal) =>
      request<Capabilities>("GET", "/capabilities", { signal, bearer: null }),

    signInWithPassword: (input: { identifier: string; password: string }) =>
      completeSignIn(() =>
        request("POST", "/password/login", { body: input, bearer: null })
      ),

    register: async (input: {
      identifier: string
      username: string
      password: string
      accountInviteToken?: string
    }): Promise<Omit<Registration, "token_set"> & { signedIn: boolean }> => {
      const gen = generation
      const out = await request<Registration>("POST", "/register", {
        bearer: null,
        body: {
          identifier: input.identifier,
          username: input.username,
          password: input.password,
          account_invite_token: input.accountInviteToken,
        },
      })
      const tokens = out.token_set ? tokenSetIn(out.token_set) : null
      if (tokens) commit(tokens, gen, "login")
      return {
        next_action: out.next_action,
        user: out.user,
        signedIn: !!tokens,
      }
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

    resendRegistration: (identifier: string) =>
      request<void>("POST", "/register/resend", {
        body: { identifier },
        bearer: null,
      }),

    // Always 204: a wrong password leaves the pending registration in place.
    abandonRegistration: (input: { identifier: string; password: string }) =>
      request<void>("POST", "/register/abandon", { body: input, bearer: null }),

    // Anonymous: resend a verification. Signed in: start a contact change.
    requestVerification: (input: { identifier: string; password?: string }) =>
      sameSession(() =>
        request<unknown>("POST", "/verify/request", { body: input })
      ).then(() => undefined),

    confirmVerification: async (
      input:
        | { identifier: string; code: string }
        | { token: string; identifier?: string }
    ): Promise<AuthOutcome | { kind: "contact_changed" }> => {
      // 204 = a signed-in contact change; otherwise a session or continuation.
      let changed = false
      try {
        return await completeSignIn(async () => {
          const body = await request<unknown>("POST", "/verify/confirm", {
            body: input,
          })
          changed = body === undefined
          return body
        })
      } catch (err) {
        if (changed) return { kind: "contact_changed" }
        throw err
      }
    },

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

    changePassword: (input: {
      currentPassword?: string
      newPassword: string
    }) =>
      sameSession(() =>
        request<unknown>("POST", "/user/password", {
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

    // Resends or switches the factor of a pending 2FA login.
    sendTwoFactorChallenge: async (input: {
      userId: string
      challenge: string
      factorId?: string
    }) => {
      const outcome = await completeSignIn(() =>
        request("POST", "/2fa/challenge", {
          bearer: null,
          body: {
            user_id: input.userId,
            challenge: input.challenge,
            factor_id: input.factorId,
          },
        })
      )
      if (outcome.kind !== "2fa_required")
        throw new Error("AuthKit returned no 2FA challenge")
      return outcome
    },

    getTwoFactor: (signal?: AbortSignal) =>
      request<TwoFactorStatus>("GET", "/user/2fa", { signal }),

    // Pass the continuation's enrollmentToken to finish a forced enrollment.
    enableTwoFactor: async (
      input: {
        method: TwoFactorMethod
        code?: string
        phoneNumber?: string
        makeDefault?: boolean
        factorId?: string
      },
      opts: { enrollmentToken?: TokenSet } = {}
    ): Promise<TwoFactorEnrollResult> => {
      const gen = generation
      let res: { status: number; body: unknown }
      try {
        res = await exchange("POST", "/user/2fa", {
          bearer: opts.enrollmentToken
            ? opts.enrollmentToken.access_token
            : undefined,
          body: {
            method: input.method,
            code: input.code,
            phone_number: input.phoneNumber,
            default: input.makeDefault,
            factor_id: input.factorId,
          },
        })
      } catch (err) {
        const continuation = readContinuation(err)
        if (continuation) return continuation
        throw err
      }
      if (res.status === 204) return { kind: "default_set" }
      if (res.status === 202) return { kind: "code_sent" }
      const body = rec(res.body)
      if (typeof body.secret === "string") {
        return {
          kind: "totp_started",
          secret: body.secret,
          otpauthUri: String(body.otpauth_uri ?? ""),
        }
      }
      const tokens = tokenSetIn(body)
      if (tokens)
        commit(tokens, gen, opts.enrollmentToken ? "login" : "refresh")
      return {
        kind: "enabled",
        method: String(body.method ?? input.method),
        backupCodes: Array.isArray(body.backup_codes)
          ? (body.backup_codes as string[])
          : [],
        signedIn: !!tokens,
        freshAuth: body.fresh_auth ? (body.fresh_auth as FreshAuth) : undefined,
      }
    },

    disableTwoFactor: (input: { factorId?: string } = {}) =>
      request<{ removed_roles: RemovedMfaRole[] }>("DELETE", "/user/2fa", {
        query: { factor_id: input.factorId },
      }).then((r) => r.removed_roles),

    regenerateBackupCodes: () =>
      request<{ backup_codes: string[] }>(
        "POST",
        "/user/2fa/backup-codes"
      ).then((r) => r.backup_codes),

    stepUpWithPassword: (password: string) =>
      sameSession(() =>
        request<{ fresh_auth: FreshAuth }>("POST", "/step-up/password", {
          body: { password },
        })
      ).then((r) => r.fresh_auth),

    // Without a code AuthKit sends one; with it the session is stepped up.
    stepUpWithTwoFactor: async (
      input: { code?: string; method?: string; backupCode?: boolean } = {}
    ): Promise<TwoFactorStepUpResult> => {
      try {
        const r = await sameSession(() =>
          request<{ fresh_auth: FreshAuth }>("POST", "/step-up/2fa", {
            body: {
              code: input.code,
              method: input.method,
              backup_code: input.backupCode,
            },
          })
        )
        return { kind: "stepped_up", freshAuth: r.fresh_auth }
      } catch (err) {
        if (err instanceof AuthKitError && err.code === "2fa_required") {
          return {
            kind: "code_sent",
            method: String(err.metadata.method ?? ""),
            verificationId: String(err.metadata.verification_id ?? ""),
          }
        }
        throw err
      }
    },

    // Returns the provider URL; AuthKit redirects back to returnTo?step_up=success|failed.
    startOidcStepUp: (provider: string, returnTo: string) =>
      request<{ auth_url: string }>(
        "POST",
        `/oidc/${encodeURIComponent(provider)}/step-up/start`,
        {
          body: { return_to: safeReturnTo(returnTo) ?? "/" },
        }
      ).then((r) => r.auth_url),

    // Returns the provider URL; completion lands as #flow=link&result=success.
    startProviderLink: (provider: string) =>
      request<{ auth_url: string }>(
        "POST",
        `/oidc/${encodeURIComponent(provider)}/link/start`,
        { body: {} }
      ).then((r) => r.auth_url),

    unlinkProvider: (provider: string, input: { password?: string } = {}) =>
      request<void>(
        "DELETE",
        `/user/providers/${encodeURIComponent(provider)}`,
        {
          body: input.password ? { password: input.password } : undefined,
        }
      ),

    listSessions: (signal?: AbortSignal) =>
      request<ListPage<UserSession>>("GET", "/user/sessions", { signal }).then(
        (r) => r.data
      ),

    revokeSessions: async (sessionIds: readonly string[]) => {
      await Promise.all(
        sessionIds.map((id) =>
          request<void>("DELETE", `/user/sessions/${encodeURIComponent(id)}`)
        )
      )
    },

    // Every session of the account, this one included.
    revokeAllSessions: async () => {
      await request<void>("DELETE", "/user/sessions")
      clear("signed_out")
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

    getPermissions: (
      input: { persona?: string; instance?: string } = {},
      signal?: AbortSignal
    ) =>
      request<PermissionSet>("GET", "/me/permissions", {
        signal,
        query: input,
      }).then((r) => r.permissions),

    updateUsername: (username: string) =>
      request<{ username: string; naming: NamingState }>(
        "PATCH",
        "/user/username",
        { body: { username } }
      ),

    updatePreferredLanguage: (language: string) =>
      request<{ preferred_language: string }>(
        "PATCH",
        "/user/preferred-language",
        {
          body: { preferred_language: language },
        }
      ).then((r) => r.preferred_language),

    deleteAccount: async (input: { password?: string } = {}) => {
      await request<void>("DELETE", "/user", {
        body: input.password ? { password: input.password } : undefined,
      })
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
      accountInviteToken?: string
    }) =>
      request<void>("POST", "/passwordless/start", {
        bearer: null,
        body: {
          identifier: input.identifier,
          mode: input.mode,
          return_to: safeReturnTo(input.returnTo) ?? undefined,
          preferred_language: input.preferredLanguage,
          account_invite_token: input.accountInviteToken,
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
    completeSignIn,
    oidcLoginUrl,
    signInWithPopup,
    completeRedirect,
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

// ?step_up=success|failed after an OIDC step-up round trip.
export function readStepUpReturn(search: string): "success" | "failed" | null {
  const v = new URLSearchParams(search).get("step_up")
  return v === "success" || v === "failed" ? v : null
}
