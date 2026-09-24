import type { AuthErrorCode } from "./generated/error-codes.ts"

export type { AuthErrorCode }
export { AUTH_ERROR_STATUS } from "./generated/error-codes.ts"

// Unknown codes must still be tolerated (SEMVER §5.2).
export type AnyAuthErrorCode = AuthErrorCode | (string & {})
