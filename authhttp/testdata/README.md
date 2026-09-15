# Cookie origin browser regression

This test uses two local sites, a real mounted AuthKit service, an isolated
Postgres database, Redis keyspace and a fresh headless browser context. It signs
in a victim,
submits three actual cross-site HTML form encodings, checks that the cookie
stays unchanged and no attacker session is created, then refreshes and logs out
from the original site, checks cookie deletion and refuses the revoked token.
No existing browser profile is opened. The isolated browser context accepts the
test server's generated TLS certificate; production transport policy is unchanged.

Install the pinned browser test dependencies with `pnpm --dir authhttp/testdata
install --frozen-lockfile`, then `pnpm --dir authhttp/testdata exec playwright
install chromium`. `task test-browser` runs the workflow, and regular CI runs it
after the Go suites. No Node dependency is added to the Go module.

To use an existing Playwright module/browser from the repository root:

```sh
AUTHKIT_TEST_DATABASE_URL='postgres://.../isolated_test_db?sslmode=disable' \
AUTHKIT_TEST_REDIS_URL='redis://127.0.0.1:6379/0' \
AUTHKIT_PLAYWRIGHT_MODULE='/path/to/node_modules/@playwright/test' \
AUTHKIT_BROWSER_EXECUTABLE='/path/to/chrome' \
go test -tags browser ./authhttp -run '^TestCookieLoginBrowserTwoSites$' -count=1 -v
```

Omit `AUTHKIT_BROWSER_EXECUTABLE` to use Playwright's installed Chromium.
The test is behind the `browser` build tag so ordinary Go-only consumers do not
need Playwright. Requesting the tag without its dependencies fails.
