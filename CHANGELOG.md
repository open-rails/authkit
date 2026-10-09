# Changelog

## v1.9.0

The owner approved shipping this breaking change in a minor release. `Client.RequirePermission` infers the group from the permission.

### Breaking

| Removed | Use instead |
|---|---|
| `MerchantConfig.Root` | nothing: a `root:` permission is checked on the root group with no configuration |

- A `root:` permission is checked on root even when `Config.Merchant.Group` is set; `Config.Merchant.Group` is only for a persona permission (such as `merchant:billing:read` in one group per merchant).
- A persona permission without `Config.Merchant.Group` still refuses everyone.
- `RequirePermission` panics on a pattern or an unregistered permission whatever the configuration (before, only when a group was configured).

Host migration: delete `Merchant: authkit.MerchantConfig{Root: true}` and pass `root:` permissions of your own to the library (for OpenRails, `Routes.Staff`). A host with one group per merchant keeps `Config.Merchant.Group`.

## v1.8.0

The owner approved shipping this breaking change in a minor release, before any external consumer exists. The delegated-token and service-JWT systems are removed. The authorization server (v1.5–v1.6) replaces them, and there is no compatibility path.

### Breaking

| Removed | Use instead |
|---|---|
| `POST /delegated/token`, `iam.RouteDelegated` | the authorization server's token endpoint: token exchange (`GrantTokenExchange`) for a signed-in user, or a code flow |
| `Client.MintDelegatedAccessToken`, `iam.DelegatedAccess` | token exchange; for a delegate acting for days, a code-flow client with `Offline`, `KeyBound` and its own `RefreshTokenTTL` |
| `Config.Delegated`, `DelegatedConfig` | `Config.AuthorizationServer`: clients, resources and per-client lifetimes |
| `Deps.DelegatedAuthorization`, `iam.DelegationAuthorizer`, `DelegationRequest`, `DelegationGrant`, `ErrDelegationRefused` | `Deps.OAuthGrants`, `iam.OAuthGrantAuthorizer`, `OAuthGrantRequest`, `OAuthGrantDecision`, `ErrOAuthGrantRefused` |
| a requested grant, the `attributes` claim | `authorization_details` (RFC 9396); the decision's URI-named `Claims` |
| a delegate certificate (`cnf.x5t#S256`) | a `KeyBound` client's DPoP key (`cnf.jkt`), which the authorizer sees as `JWKThumbprint` |
| `Client.MintServiceJWT`, `iam.ServiceJWT`, `ServiceJWTClaims`, `ServiceJWTTokenUse`, `DefaultServiceJWTLifetime`, `ErrInvalidServiceJWT` | client credentials (`GrantClientCredentials`) |
| `Client.VerifyServiceJWT`, `Verifier.VerifyServiceJWT`, `verify.Verifier.VerifyServiceJWT`, `verify.WithServiceJWTMaxLifetime`, `ServiceJWTVerifyOption` | verify the client-credentials `at+jwt` with `verify.Verifier` (`Claims.Kind` is `iam.ActorOAuthClient`) |
| the `delegated-access+jwt`, `remote-application-access+jwt` and `service+jwt` token types | `at+jwt`: AuthKit's `verify` refuses the old types |
| `iam.DelegatedIdentity`, `iam.DelegatedGrant`, `CredentialState.Delegated`, `DelegatedIssuer` | `iam.InSession(iam.UserIdentity(id), ref)`; a resource token's authority is `verify.Claims.Permissions` |
| `verify.Claims.DelegatedSubject`, `Attributes`, `RemoteApplicationID`; `verify.TokenDelegated`, `TokenRemoteApplication` | `Subject`, `AuthorizationDetails`, `CustomClaims`, `Invoker` |
| AuthKit authenticating a remote application's own tokens | a resource server's own `verify.Verifier`, fed from `Client.RemoteApplication` (keys or JWKS URI; `Permissions` is the ceiling). The remote-application registry stays. |
| `Client.CheckIssuerKeys`, `Client.IssuerKeyStatuses`, `Verifier.CheckIssuerKeys`, `Verifier.IssuerKeyStatuses` | nothing: AuthKit's own verifier trusts only its own keys. A resource server's `verify.Verifier.CheckIssuerKeys` still reports its issuers. |
| the `delegated_token_mint` rate-limit bucket | nothing: `Config.RateLimits` now refuses that name |
| error codes `access_token_has_sub`, `access_token_wrong_typ`, `conflicting_subject`, `delegated_access_wrong_typ`, `delegation_authorizer_unavailable`, `delegation_refused`, `invalid_audiences`, `invalid_delegate_certificate`, `invalid_requested_grant`, `invalid_service_jwt`, `malformed_permissions`, `missing_delegated_sub`, `missing_iat`, `missing_nbf`, `not_delegated_access_token`, `permission_not_granted`, `remote_application_access_has_subject`, `service_jwt_lifetime_exceeded`, `ttl_exceeds_delegate_certificate` | `oauth_grant_refused` / `oauth_grant_authorizer_unavailable`, or the OAuth error a token endpoint answers |

Also breaking, from #397:
- **Migrations**: `authkit.Migrate`, `MigrateOptions` and `RuntimePool` are deleted, along with the runtime-role grants. `New` now migrates AuthKit's and River's tables through `Deps.Postgres`, whose role owns and uses them. `Config.Schema` and `Config.RiverSchema` move to `Config.Database` (`DatabaseConfig`). The `cmd/authkit-migrate` command is gone.
