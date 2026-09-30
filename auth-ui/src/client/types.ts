// AuthKit's wire shapes. The HTTP API's are generated from the Go route
// catalog (generated/wire.ts, `go generate ./internal/httpapi`); the rest are
// the error metadata and names the client adds.
export type * from "./generated/wire.ts"

export type TwoFactorMethod = "email" | "sms" | "totp"

// A session's tokens as the client reads them from any transport (a JSON
// TokenSet, a login fragment, a popup message).
export type SessionTokens = {
  access_token: string
  token_type?: string
  expires_in?: number
  // Present only on mounts without the refresh cookie.
  refresh_token?: string
}

// Metadata of 429 rate_limited and rename_rate_limited.
export type ActionAvailability = {
  action: string
  allowed: boolean
  reason: string
  retry_after_seconds: number
  next_allowed_at: string | null
  limit: number | null
  remaining: number | null
  window_seconds: number | null
  cooldown_seconds: number | null
}

// metadata.recovery of 409 account_recovery_required.
export type AccountRecovery = {
  token: string
  expires_at: string
  purge_at: string
}
