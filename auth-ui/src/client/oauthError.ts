// An OAuth 2.0 protocol error (RFC 6749 §5.2): the token endpoint's
// {error, error_description}, or an authorization response's error.
export class OAuthError extends Error {
  readonly status: number
  readonly error: string
  readonly description?: string

  constructor(status: number, error: string, description?: string) {
    super(description ? `${error}: ${description}` : error)
    this.name = "OAuthError"
    this.status = status
    this.error = error
    this.description = description
  }
}

export const isOAuthError = (e: unknown): e is OAuthError =>
  e instanceof OAuthError

// Reads a token endpoint's error answer.
export async function readOAuthError(res: Response): Promise<OAuthError> {
  const body = (await res.json().catch(() => ({}))) as Record<string, unknown>
  return new OAuthError(
    res.status,
    typeof body.error === "string" ? body.error : "server_error",
    typeof body.error_description === "string"
      ? body.error_description
      : undefined
  )
}
