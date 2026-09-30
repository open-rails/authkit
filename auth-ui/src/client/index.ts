export { createAuthClient, readLinkFragment } from "./client.ts"
export type {
  AuthClient,
  AuthClientOptions,
  AuthSession,
  ContactProofHandler,
  ContactProofRequest,
  LinkFragment,
  PopupResult,
  RedirectResult,
  RefreshTokenStorage,
  RequestOptions,
  SessionHint,
  SessionHintOptions,
  TwoFactorEnrolled,
} from "./client.ts"
export { toSignInResult } from "./authResult.ts"
export type { PendingSignIn, SignInResult } from "./authResult.ts"
export { AUTH_ERROR_STATUS } from "./codes.ts"
export type {
  AnyAuthErrorCode,
  AuthErrorCode,
  AuthErrorMetadata,
} from "./codes.ts"
export {
  AuthKitError,
  AuthSessionChangedError,
  errorMetadata,
  isAuthKitError,
  readAuthKitError,
  retryAfterSeconds,
} from "./errors.ts"
export type { AuthKitErrorBody } from "./errors.ts"
export { decodeAccessClaims } from "./jwt.ts"
export type { AccessClaims } from "./jwt.ts"
export { hasPermission } from "./permissions.ts"
export { safeReturnTo } from "./returnTo.ts"
export { readStepUpRequired, stepUpDestination } from "./stepUp.ts"
export type { StepUpChallenge } from "./stepUp.ts"
export type * from "./types.ts"
