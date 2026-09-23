// Mirrors authkit.WriteError: {"error":{"type","code","message","param?","metadata?"}}.
export type AuthKitErrorBody = {
  type: string
  code: string
  message: string
  param?: string
  metadata?: Record<string, unknown>
}

export class AuthKitError extends Error {
  readonly status: number
  readonly type: string
  readonly code: string
  readonly param?: string
  readonly metadata: Record<string, unknown>

  constructor(status: number, body: AuthKitErrorBody) {
    super(body.message)
    this.name = "AuthKitError"
    this.status = status
    this.type = body.type
    this.code = body.code
    this.param = body.param
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
  if (err && typeof err.code === "string") {
    return new AuthKitError(res.status, {
      type: err.type ?? "",
      code: err.code,
      message: err.message ?? err.code,
      param: err.param,
      metadata: err.metadata,
    })
  }
  return new AuthKitError(res.status, {
    type: "",
    code: "unknown_error",
    message: `HTTP ${res.status}`,
  })
}
