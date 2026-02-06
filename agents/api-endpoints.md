# AuthKit API Endpoints Reference

All endpoints are under `/api/v1/auth` unless otherwise noted.

## Authentication Levels

| Level | Description |
|-------|-------------|
| **PUBLIC** | No authentication required. |
| **AUTH** | Requires valid JWT token (logged-in user). |
| **ADMIN** | Requires valid JWT with admin role. |

---

## JWKS (Root)

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | `/.well-known/jwks.json` | PUBLIC | JWKS public keys |

---

## OIDC Browser Flows (Root)

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | `/auth/oidc/:provider/login` | PUBLIC | Start OIDC login (Google, Apple, etc.) |
| GET | `/auth/oidc/:provider/callback` | PUBLIC | OIDC callback |
| GET | `/auth/oauth/discord/login` | PUBLIC | Discord OAuth login |
| GET | `/auth/oauth/discord/callback` | PUBLIC | Discord OAuth callback |

---

## Registration & Login

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| POST | `/auth/password/login` | PUBLIC | Password login (org_mode=multi: optional `org` in body to mint org-scoped access token) |
| POST | `/auth/register` | PUBLIC | Unified registration (email or phone) |
| POST | `/auth/register/resend-email` | PUBLIC | Resend email verification |
| POST | `/auth/register/resend-phone` | PUBLIC | Resend phone verification |
| POST | `/auth/token` | PUBLIC | Refresh access token (org_mode=multi: optional `org` in body to mint org-scoped access token) |
| POST | `/auth/sessions/current` | PUBLIC | Get current session info |

---

## Password Reset

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| POST | `/auth/password/reset/request` | PUBLIC | Request password reset (email) |
| POST | `/auth/password/reset/confirm` | PUBLIC | Confirm password reset (token from reset link; legacy field name is `code`) |
| POST | `/auth/password/reset/confirm-link` | PUBLIC | Confirm password reset (expects `token`) |
| POST | `/auth/phone/password/reset/request` | PUBLIC | Request password reset (phone) |
| POST | `/auth/phone/password/reset/confirm` | PUBLIC | Confirm password reset (token from reset link; legacy) |

---

## Email/Phone Verification

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| POST | `/auth/email/verify/request` | PUBLIC | Request email verification |
| POST | `/auth/email/verify/confirm` | PUBLIC | Confirm email verification |
| POST | `/auth/email/verify/confirm-link` | PUBLIC | Confirm email verification (expects `token`) |
| POST | `/auth/phone/verify/request` | PUBLIC | Request phone verification (sends SMS) |
| POST | `/auth/phone/verify/confirm` | PUBLIC | Confirm phone verification |

---

## User Management (Authenticated)

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | `/auth/user/me` | AUTH | Get current user (org_mode=multi: includes `orgs` list with per-org roles) |
| GET | `/auth/user/bootstrap` | AUTH | Get canonical personal org + org memberships/roles for bootstrap |
| PATCH | `/auth/user/username` | AUTH | Change username |
| PATCH | `/auth/user/biography` | AUTH | Update biography |
| POST | `/auth/user/password` | AUTH | Change password |
| POST | `/auth/user/email/change/request` | AUTH | Request email change |
| POST | `/auth/user/email/change/confirm` | AUTH | Confirm email change |
| POST | `/auth/user/email/change/resend` | AUTH | Resend email change verification |
| POST | `/auth/user/phone/change/request` | AUTH | Request phone number change |
| POST | `/auth/user/phone/change/confirm` | AUTH | Confirm phone number change |
| POST | `/auth/user/phone/change/resend` | AUTH | Resend phone number change verification |
| DELETE | `/auth/user` | AUTH | Delete own account |
| DELETE | `/auth/user/providers/:provider` | AUTH | Unlink OAuth provider |

---

## Organizations (org_mode=multi only)

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | `/auth/orgs` | AUTH | List orgs for current user (includes per-org roles) |
| POST | `/auth/orgs` | AUTH | Create an org (creator is bootstrapped as `owner`) |
| GET | `/auth/orgs/:org` | AUTH | Get org metadata (`:org` accepts slug or alias) |
| POST | `/auth/orgs/:org/rename` | AUTH | Rename org slug (keeps old slug as alias) |
| GET | `/auth/orgs/:org/members` | AUTH | List members (org owner) |
| POST | `/auth/orgs/:org/members` | AUTH | Add member (org owner) |
| DELETE | `/auth/orgs/:org/members` | AUTH | Remove member (org owner) |
| GET | `/auth/orgs/:org/invites` | AUTH | List org invites (org owner) |
| POST | `/auth/orgs/:org/invites` | AUTH | Create invite (org owner) |
| POST | `/auth/orgs/:org/invites/:invite_id/revoke` | AUTH | Revoke pending invite (org owner) |
| GET | `/auth/org-invites` | AUTH | List invites for current user |
| POST | `/auth/org-invites/:invite_id/accept` | AUTH | Accept invite as current user |
| POST | `/auth/org-invites/:invite_id/decline` | AUTH | Decline invite as current user |
| GET | `/auth/orgs/:org/roles` | AUTH | List defined roles (org owner) |
| POST | `/auth/orgs/:org/roles` | AUTH | Define role (org owner; `owner` is protected) |
| DELETE | `/auth/orgs/:org/roles` | AUTH | Delete role (org owner; `owner` is protected) |
| GET | `/auth/orgs/:org/members/:user_id/roles` | AUTH | Read member roles (org owner) |
| POST | `/auth/orgs/:org/members/:user_id/roles` | AUTH | Assign role to member (org owner; only owner can grant `owner`) |
| DELETE | `/auth/orgs/:org/members/:user_id/roles` | AUTH | Unassign role from member (org owner; cannot remove last owner) |
| POST | `/auth/token/org` | AUTH | Mint org-scoped access token (`org` + `roles`) |

---

## Sessions

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | `/auth/user/sessions` | AUTH | List user sessions |
| DELETE | `/auth/user/sessions/:id` | AUTH | Revoke specific session |
| DELETE | `/auth/user/sessions` | AUTH | Revoke all sessions |
| DELETE | `/auth/logout` | AUTH | Logout current session |

---

## Two-Factor Authentication

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | `/auth/user/2fa` | AUTH | Get 2FA status |
| POST | `/auth/user/2fa/start-phone` | AUTH | Start phone-based 2FA enrollment |
| POST | `/auth/user/2fa/enable` | AUTH | Enable 2FA |
| POST | `/auth/user/2fa/disable` | AUTH | Disable 2FA |
| POST | `/auth/user/2fa/regenerate-codes` | AUTH | Regenerate backup codes |
| POST | `/auth/2fa/verify` | PUBLIC | Verify 2FA code during login |

---

## Provider Linking

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| POST | `/auth/oidc/:provider/link/start` | AUTH | Start OIDC provider linking |
| POST | `/auth/oauth/discord/link/start` | AUTH | Start Discord linking |

---

## Solana (Sign-In With Solana)

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| POST | `/auth/solana/challenge` | PUBLIC | Get SIWS challenge nonce |
| POST | `/auth/solana/login` | PUBLIC | Login with signed Solana message |
| POST | `/auth/solana/link` | AUTH | Link Solana wallet to account |

---

## Admin

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| POST | `/auth/admin/roles/grant` | ADMIN | Grant role to user |
| POST | `/auth/admin/roles/revoke` | ADMIN | Revoke role from user |
| GET | `/auth/admin/users` | ADMIN | List users |
| GET | `/auth/admin/users/:user_id` | ADMIN | Get user details |
| POST | `/auth/admin/users/ban` | ADMIN | Ban user |
| POST | `/auth/admin/users/unban` | ADMIN | Unban user |
| POST | `/auth/admin/users/set-email` | ADMIN | Set user email |
| POST | `/auth/admin/users/set-username` | ADMIN | Set user username |
| POST | `/auth/admin/users/set-password` | ADMIN | Set user password |
| POST | `/auth/admin/users/toggle-active` | ADMIN | Toggle user active status |
| DELETE | `/auth/admin/users/:user_id` | ADMIN | Delete user |
| POST | `/auth/admin/users/:user_id/restore` | ADMIN | Restore (undelete) user |
| GET | `/auth/admin/users/deleted` | ADMIN | List deleted users |
