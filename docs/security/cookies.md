# Cookie compatibility

Browsers keep cookies across AuthKit upgrades, so a cookie's shape is a
contract. `authhttp/cookies.go` holds the registry of every refresh and OIDC
state cookie variant AuthKit has ever issued (name, path, domain, `Secure`):

- Setting or rotating a cookie expires the historical variants the browser
  still sends; sign-out expires every variant.
- The refresh reader prefers the current variant. A lone historical cookie is
  read and migrated to the current one until its `AcceptUntil` (historical
  plain names can be planted by a sibling subdomain, so this is time-boxed).
- More values of one name than registered paths for it is a same-path
  duplicate (cookie tossing) and is refused.
- Historical OIDC state cookies are never read (a flow lasts 15 minutes); they
  are only expired.

**Changing a cookie** (name, path, domain, prefix): add the new shape as a new
registry variant marked `Current`, keep the old one as historical, and append it
to `authhttp/testdata/cookie-registry.golden`. Never edit or remove a variant
or a golden line. `TestCookieRegistry` fails when the cookies AuthKit sets
differ from the registry's current variants or the registry differs from the
golden list; `TestSecurityRefreshCookieUpgrade` proves an earlier release's jar
stays signed in.

| Cookie | Current | Historical |
|---|---|---|
| Refresh, HTTPS | `__Host-authkit_rt`, `Path=/` | `authkit_rt`, `Path={api}/token` (≤ v0.136.0) |
| Refresh, HTTP (dev) | `authkit_rt`, `Path=/` | `authkit_rt`, `Path={api}/token` (≤ v0.136.0) |
| OIDC state, HTTPS | `__Host-authkit_oauth_state_<id>`, `Path=/` | `authkit_oauth_state_<id>` (≤ v0.136.0) |
| OIDC state, HTTP (dev) | `authkit_oauth_state_<id>`, `Path=/` | — |
