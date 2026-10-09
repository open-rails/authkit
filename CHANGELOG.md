# Changelog

## v1.10.1

- A TOTP key file readable by its group (0440, as a Kubernetes secret volume with `fsGroup` mounts it) loads without a warning (#439). World-read still warns; any group or world write bit is still refused.
- Building a client without `Deps.OnEvent` no longer turns account events off for its issuer (#440). A verify-only, ops or test client on the same database and issuer used to stop the server's events until it restarted. `New` with `OnEvent` subscribes the issuer; `New` without it changes nothing. `Start` of the client running the issuer's fleet sets the subscription to whether it handles events: a fleet run without a handler unsubscribes and drains what is pending.

## v1.10.0

Additive.

- **JWT-bearer grant with device-key capabilities** (#437, RFC 7523). A workload acts for a user only through a capability the user's device key signs offline with `devicekey.SignCapability`. The capability names the resource, the operations (`authorization_details`), the workload's P-256 key (`cnf.jkt`) and an expiry of at most 24 hours. The workload posts an ES256 `assertion` signed by its own key (`jwk` header, `iss` the client, `aud` the token endpoint, a single-use `jti`) that carries the capability, with a DPoP proof of the same key.
  - A client opts in with `GrantJWTBearer` and its `AuthorizationDetailsTypes`. It may be public, and it needs `DeviceKeys.Enabled` and `Deps.OAuthGrants`.
  - AuthKit verifies both signatures, the device key's liveness and the key binding. The grant authorizer then sees `iam.OAuthGrantJWTBearer` with `UserID`, `DeviceKeyID`, the operations, `JWKThumbprint`, `iam.OAuthAssertion` and `iam.OAuthCapability`. It may refuse, or narrow the operations by dropping entries. `OAuthGrantDecision.Invoker` names the workload in `act`.
  - The `at+jwt` lasts until the capability expires and carries `device_key_id`, with no refresh token. `Client.CheckSession` and `verify.RequireSession` now check that device key for this issuer's jwt-bearer tokens, so revoking the key ends them at once. `verify.Claims.DeviceKeyID` is now kept for a local issuer's resource tokens.
  - Refusals carry a `reason` beside the OAuth `error`. Discovery lists the grant type. See [Workloads](docs/authorization-server.md#workloads).
- `authtest`: `DeviceKey.UserID`, `DeviceKey.Capability`, `RevokeDeviceKey`, `DPoPKey.Assertion`, `AuthorizationServer.JWTBearer`, `JWTBearerToken` and `TokenEndpoint`.

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
