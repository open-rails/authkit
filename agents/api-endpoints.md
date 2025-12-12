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
| POST | `/auth/password/login` | PUBLIC | Password login |
| POST | `/auth/register` | PUBLIC | Unified registration (email or phone) |
| POST | `/auth/register/resend-email` | PUBLIC | Resend email verification |
| POST | `/auth/register/resend-phone` | PUBLIC | Resend phone verification |
| POST | `/auth/token` | PUBLIC | Refresh access token |
| POST | `/auth/sessions/current` | PUBLIC | Get current session info |

---

## Password Reset

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| POST | `/auth/password/reset/request` | PUBLIC | Request password reset (email) |
| POST | `/auth/password/reset/confirm` | PUBLIC | Confirm password reset |
| POST | `/auth/phone/password/reset/request` | PUBLIC | Request password reset (phone) |
| POST | `/auth/phone/password/reset/confirm` | PUBLIC | Confirm password reset (phone) |

---

## Email/Phone Verification

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| POST | `/auth/email/verify/request` | PUBLIC | Request email verification |
| POST | `/auth/email/verify/confirm` | PUBLIC | Confirm email verification |
| POST | `/auth/phone/verify/request` | PUBLIC | Request phone verification (sends SMS) |
| POST | `/auth/phone/verify/confirm` | PUBLIC | Confirm phone verification |

---

## User Management (Authenticated)

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | `/auth/user/me` | AUTH | Get current user |
| PATCH | `/auth/user/username` | AUTH | Change username |
| PATCH | `/auth/user/biography` | AUTH | Update biography |
| POST | `/auth/user/password` | AUTH | Change password |
| POST | `/auth/user/email/change/request` | AUTH | Request email change |
| POST | `/auth/user/email/change/confirm` | AUTH | Confirm email change |
| POST | `/auth/user/email/change/resend` | AUTH | Resend email change verification |
| DELETE | `/auth/user` | AUTH | Delete own account |
| DELETE | `/auth/user/providers/:provider` | AUTH | Unlink OAuth provider |

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
| DELETE | `/auth/admin/users/:user_id` | ADMIN | Delete user |
| GET | `/auth/admin/users/:user_id/signins` | ADMIN | Get user sign-in history |
