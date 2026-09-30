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
    code: "unknown_error",
    message: `HTTP ${res.status}`,
    metadata,
  })
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
