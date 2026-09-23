// Unverified read of access-token claims; the server remains authoritative.
export type AccessClaims = {
  sub?: string
  sid?: string
  exp?: number
  iat?: number
  auth_time?: number
  amr?: string[]
  entitlements?: string[]
  // Delegated tokens carry concrete permissions and no sub.
  delegated_sub?: string
  permissions?: string[]
  [claim: string]: unknown
}

export function decodeAccessClaims(token: string): AccessClaims | null {
  const part = token.split(".")[1]
  if (!part) return null
  try {
    const b64 = part.replace(/-/g, "+").replace(/_/g, "/")
    const padded = b64 + "=".repeat((4 - (b64.length % 4)) % 4)
    const bytes = Uint8Array.from(atob(padded), (c) => c.charCodeAt(0))
    const claims: unknown = JSON.parse(new TextDecoder().decode(bytes))
    return claims && typeof claims === "object"
      ? (claims as AccessClaims)
      : null
  } catch {
    return null
  }
}

export const principalOf = (claims: AccessClaims | null): string | undefined =>
  claims?.sub ?? claims?.delegated_sub
