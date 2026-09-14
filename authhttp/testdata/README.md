# Cookie origin browser regression

This test uses two local sites, a real mounted AuthKit service, an isolated
Postgres database, Redis keyspace and a fresh headless browser context. It signs
in a victim,
submits three actual cross-site HTML form encodings, checks that the cookie
stays unchanged and no attacker session is created, then refreshes and logs out
from the original site, checks cookie deletion and refuses the revoked token.
No existing browser profile is opened. The isolated browser context accepts the
test server's generated TLS certificate; production transport policy is unchanged.

Use an installed Playwright module and browser; no Node dependency is added to
the Go module. From the repository root:

```sh
AUTHKIT_TEST_DATABASE_URL='postgres://.../isolated_test_db?sslmode=disable' \
AUTHKIT_TEST_REDIS_URL='redis://127.0.0.1:6379/0' \
AUTHKIT_PLAYWRIGHT_MODULE='/path/to/node_modules/@playwright/test' \
AUTHKIT_BROWSER_EXECUTABLE='/path/to/chrome' \
go test -tags browser ./authhttp -run '^TestCookieLoginBrowserTwoSites$' -count=1 -v
```

Omit `AUTHKIT_BROWSER_EXECUTABLE` to use Playwright's installed Chromium.
The test is behind the `browser` build tag because regular Go CI has no browser
or Playwright installation; requesting the tag without those dependencies fails.
