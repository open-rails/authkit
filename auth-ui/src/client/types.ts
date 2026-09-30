// Wire shapes of AuthKit's browser surface (authkit wire.go, authhttp/*).

export type TokenSet = {
  access_token: string
  token_type?: string
  expires_in?: number
  // Present only on mounts without the refresh cookie.
  refresh_token?: string
}

export type ListPage<T> = {
  object: "list"
  data: T[]
  next_cursor?: string
}

export type Capabilities = {
  registration: { mode: string; invite_token_required: boolean }
  external_login_providers: ExternalLoginProvider[]
  username: UsernamePolicy
  password: PasswordPolicy
  passwordless: { enabled: boolean; channels?: string[] }
  passkeys: { login: boolean }
  solana: { login: boolean }
  verification: { registration: string }
  // Which contact channels can deliver now (SMS: its latest health check passed).
  channels?: { email: boolean; sms: boolean }
  languages?: string[]
  // The serving mount's anchors as full paths; unmounted ones are omitted.
  paths?: { api: string; oidc?: string; jwks?: string }
}

// Naming and password policy AuthKit advertises.
export type UsernamePolicy = {
  min_length: number
  max_length: number
  pattern: string
  // Whether users may rename themselves, how often, and how long a former
  // username stays reserved for its owner.
  renames?: boolean
  rename_interval_seconds?: number
  former_names?: NamingPolicy
}

export type PasswordPolicy = {
  min_length: number
  max_length: number
  require_uppercase: boolean
  require_lowercase: boolean
  require_digit: boolean
  require_symbol: boolean
  reject_common: boolean
}

export type ExternalLoginProvider = {
  id: string
  name: string
  supports_login: boolean
  supports_registration: boolean
  supports_link: boolean
}

export type TwoFactorMethod = "email" | "sms" | "totp"

export type TwoFactorFactor = {
  id?: string
  method: string
  is_default?: boolean
  phone_number?: string | null
  /** Masked address an email factor's codes go to. */
  email?: string
}

export type TwoFactorStatus = {
  enabled: boolean
  method: string
  phone_number?: string
  default_factor?: TwoFactorFactor
  factors?: TwoFactorFactor[]
  allowed_methods?: string[]
  backup_codes_remaining?: number
}

export type FreshAuth = {
  step_up_required_for_sensitive_actions: boolean
  time_until_step_up_required: number
  last_authenticated_at?: string
  auth_methods?: string[]
}

export type StepUpTwoFactorOptions = {
  methods?: string[]
  default_method?: string
  options?: { method: string; is_default?: boolean; verification_id?: string }[]
}

export type UserSecurity = {
  last_authenticated_at?: string
  time_until_step_up_required?: number
  step_up_required_for_sensitive_actions: boolean
  step_up_methods?: string[]
  step_up_2fa?: StepUpTwoFactorOptions
  mfa_enabled: boolean
  mfa_satisfied: boolean
  mfa_allowed_methods?: string[]
}

export type NamingPolicy = {
  enabled: boolean
  former_name_retention_mode: "finite" | "forever" | "immediate"
  former_name_retention_seconds: number
}

export type NamingState = {
  aliases?: { name: string; expires_at?: string | null }[]
  policy: NamingPolicy
  allowed: boolean
  next_rename_at?: string | null
  retry_after_seconds: number
}

export type ActionAvailability = {
  action: string
  allowed: boolean
  reason?: string
  retry_after_seconds?: number
  next_allowed_at?: string | null
  limit?: number
  remaining?: number
  window_seconds?: number
  cooldown_seconds?: number
}

export type SolanaLinkedAccount = {
  provider: "solana"
  issuer: string
  address: string
  verified: boolean
  verified_at: string | null
  primary_sns_name: string | null
  sns_resolution_status:
    "disabled" | "pending" | "resolved" | "not_found" | "error" | "stale"
  sns_resolved_at: string | null
  sns_stale: boolean
  sns_error: string | null
}

// GET /me
export type UserProfile = {
  id: string
  username: string
  email: string | null
  phone_number: string | null
  email_verified: boolean
  phone_verified: boolean
  has_password: boolean
  solana_linked_account?: SolanaLinkedAccount
  linked_providers?: string[]
  roles: string[]
  entitlements: string[]
  avatar_url?: string
  preferred_language?: string
  created_at?: string
  naming: NamingState
  security: UserSecurity
}

export type UserSession = {
  session_id: string
  family_id: string
  created_at: string
  last_used_at: string
  expires_at: string
  ip?: string
  ua?: string
}

export type RegistrationNextAction = "none" | "verify_email" | "verify_phone"

export type Registration = {
  next_action: RegistrationNextAction
  user: { username: string; email: string | null; phone_number: string | null }
  token_set?: TokenSet
}

export type AvailabilityField = { available: boolean; error?: string }

export type Availability = {
  username?: AvailabilityField
  email?: AvailabilityField
  phone_number?: AvailabilityField
}

export type RemovedMfaRole = {
  permission_group_id: string
  persona: string
  role: string
  removed_at: string
}

export type PermissionSet = {
  group_id: string
  permissions: string[]
}

export type AccountRecovery = {
  token: string
  expires_at: string
  purge_at: string
}
