import type { AnyAuthErrorCode, AuthErrorMetadata } from "./codes.ts"

// AuthKit's error envelope: {"error":{"type","code","message","param","metadata"}}.
export type AuthKitErrorBody = {
  type: string
  code: AnyAuthErrorCode
  message: string
  param?: string | null
  metadata?: Record<string, unknown> | null
}

export class AuthKitError extends Error {
  readonly status: number
  readonly type: string
  readonly code: AnyAuthErrorCode
  readonly param?: string
  // {} when the code carries none; errorMetadata() reads it typed.
  readonly metadata: Record<string, unknown>

  constructor(status: number, body: AuthKitErrorBody) {
    super(body.message)
    this.name = "AuthKitError"
    this.status = status
    this.type = body.type
    this.code = body.code
    this.param = body.param ?? undefined
    this.metadata = body.metadata ?? {}
  }

  get retryAfterSeconds(): number | undefined {
    const v = this.metadata.retry_after_seconds
    return typeof v === "number" ? v : undefined
  }
}

export async function readAuthKitError(res: Response): Promise<AuthKitError> {
  let body: unknown
  try {
    body = await res.json()
  } catch {
    body = undefined
  }
  const err = (body as { error?: Partial<AuthKitErrorBody> } | undefined)?.error
  const retryAfter = retryAfterSeconds(res.headers.get("Retry-After"))
  const metadata = { ...(err?.metadata ?? {}) }
  if (
    retryAfter !== undefined &&
    typeof metadata.retry_after_seconds !== "number"
  ) {
    metadata.retry_after_seconds = retryAfter
  }
  if (err && typeof err.code === "string") {
    return new AuthKitError(res.status, {
      type: err.type ?? "",
      code: err.code,
      message: err.message ?? err.code,
      param: err.param,
      metadata,
    })
  }
  return new AuthKitError(res.status, {
    type: "",
    code: GATEWAY_STATUS.has(res.status)
      ? "server_unavailable"
      : "unknown_error",
    message: `HTTP ${res.status}`,
    metadata,
  })
}

// A gateway answered for AuthKit: down, restarting or timed out (52x: Cloudflare).
const GATEWAY_STATUS = new Set([502, 503, 504, 520, 521, 522, 523, 524])

// fetch rejects with a TypeError when no server answers (offline, DNS,
// connection refused, CORS); engines word it differently.
const FETCH_FAILURE = /fetch|network|load failed|connection/i

// Local codes for a request AuthKit never answered: "network_error" when it
// reached no server, "server_unavailable" when a gateway or timeout answered.
export function transportFailure(
  error: unknown
): "network_error" | "server_unavailable" | undefined {
  if (error instanceof TypeError) {
    const offline = globalThis.navigator?.onLine === false
    return offline || FETCH_FAILURE.test(error.message)
      ? "network_error"
      : undefined
  }
  if (!error || typeof error !== "object") return undefined
  const { name, code, status } = error as {
    name?: unknown
    code?: unknown
    status?: unknown
  }
  if (name === "TimeoutError") return "server_unavailable"
  if (code === "network_error" || code === "server_unavailable") return code
  if (code === undefined || code === "unknown_error")
    return typeof status === "number" && GATEWAY_STATUS.has(status)
      ? "server_unavailable"
      : undefined
  return undefined
}

// Retry-After is delta-seconds or an HTTP date.
export function retryAfterSeconds(header: string | null): number | undefined {
  if (!header) return undefined
  const seconds = Number(header)
  if (Number.isFinite(seconds)) return Math.max(0, seconds)
  const at = Date.parse(header)
  return Number.isFinite(at)
    ? Math.max(0, Math.ceil((at - Date.now()) / 1000))
    : undefined
}

export const isAuthKitError = (value: unknown): value is AuthKitError =>
  value instanceof AuthKitError

// The metadata of an AuthKit error with this code, typed per the contract;
// null for any other error.
export function errorMetadata<C extends keyof AuthErrorMetadata>(
  error: unknown,
  code: C
): AuthErrorMetadata[C] | null {
  return error instanceof AuthKitError && error.code === code
    ? (error.metadata as AuthErrorMetadata[C])
    : null
}

// A flow finished after the session it started under was replaced or ended.
export class AuthSessionChangedError extends Error {
  constructor() {
    super("The authentication session changed. Please try again.")
    this.name = "AuthSessionChangedError"
  }
}
