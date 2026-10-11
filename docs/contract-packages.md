# Authentication and user-directory contracts

`github.com/open-rails/authkit/auth` owns the request authentication contract: `Authenticator`, `Verified`, identity, scope, optional capabilities and standardized refusals. `github.com/open-rails/authkit/userinfo` owns the host directory's `Lookup` and `User`. These are the implementations previously published under `github.com/open-rails/helpers`, including `auth.Asserted`.

Both packages depend only on the standard library. They do not import the AuthKit root package, its engine, database clients or initialization. A library can accept these contracts from a custom host authenticator or directory without running AuthKit. Importing the contracts adds the AuthKit module to the Go module graph; it does not link the AuthKit service implementation.

`auth/authtest.Check` tests a host authenticator's permissions, credential bounds, assertions and refusals. `userinfo/userinfotest.Check` tests current user lookup and search. They depend on their contract package and the standard library. AuthKit's existing root `authtest` package remains the separate integration harness that runs a real AuthKit client.

## Migration

Update AuthKit and each library or host that exchanges these types together. Replace imports as follows, including test imports:

| Previous import | Current import |
| --- | --- |
| `github.com/open-rails/helpers/auth` | `github.com/open-rails/authkit/auth` |
| `github.com/open-rails/helpers/auth/authtest` | `github.com/open-rails/authkit/auth/authtest` |
| `github.com/open-rails/helpers/userinfo` | `github.com/open-rails/authkit/userinfo` |
| `github.com/open-rails/helpers/userinfo/userinfotest` | `github.com/open-rails/authkit/userinfo/userinfotest` |

Keep existing import aliases where names collide. Custom implementations keep the same methods and behavior, but their parameter and result types must come from the new imports. Go named types belong to their defining package: the old `Identity`, `Scope`, `Credential` and `User` types do not satisfy signatures using the new types. This changes AuthKit public methods that exchange these types, including identity constructors, authorization operations, `Authenticator()` and `UserInfo()`.

There are no compatibility aliases or forwarding implementations. An application must not mix a library compiled against the old contracts with an authenticator returning the new contracts. Runtime wire formats and authentication behavior are unchanged.

A library that previously rejected every AuthKit import can instead allow only these contract and conformance packages and verify their standard-library dependency closure. The AuthKit root package and implementation packages remain outside that boundary.

The shared `helpers/api`, `helpers/api/gin`, `helpers/smtp`, `helpers/river` and `helpers/deps` packages are unaffected. Keep the helpers module requirement when using them. Removal of helpers' former auth and userinfo packages is a separate consumer-coordinated change.
