# Cookie origin browser regression

`TestCookieLoginBrowserTwoSites` serves a real Client (authtest, scratch schema)
on one local TLS site and a cross-site form on another, then drives a fresh
headless browser context. It signs in a victim, submits three cross-site HTML
form encodings, checks that the refresh cookie stays unchanged and no attacker
session is created, then refreshes and logs out from the original site, checks
cookie deletion and refuses the revoked token. No existing browser profile is
opened; the context accepts the test server's generated TLS certificate.

Install the pinned dependencies with `pnpm --dir internal/apitest/testdata install
--frozen-lockfile`, then `pnpm --dir internal/apitest/testdata exec playwright
install chromium`. `scripts/check.sh workflows` and CI run it after the Go
suites. No Node dependency is added to the Go module.

To use an existing Playwright module and browser from the repository root:

```sh
AUTHKIT_TEST_DATABASE_URL='postgres://.../isolated_test_db?sslmode=disable' \
AUTHKIT_PLAYWRIGHT_MODULE='/path/to/node_modules/@playwright/test' \
AUTHKIT_BROWSER_EXECUTABLE='/path/to/chrome' \
go test -tags browser ./internal/apitest -run '^TestCookieLoginBrowserTwoSites$' -count=1 -v
```

Omit `AUTHKIT_BROWSER_EXECUTABLE` to use Playwright's installed Chromium. The
`browser` build tag keeps Playwright out of ordinary Go runs; requesting the tag
without its dependencies fails.
