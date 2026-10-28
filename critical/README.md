AuthKit's critical suite exercises the public embedded Go client, the mounted HTTP server, real Gin/Fiber adapters, PostgreSQL, Redis, and River. Email/SMS delivery is captured at the external sender boundary. External issuer failures use local TLS servers; storage outages cut a real owned TCP connection. No AuthKit service or authorization result is mocked.

The four J36 configured-group cases exercise `EnsureGroups` with a one-connection
caller pool and no runtime configuration, preserving memberships and create
events on replay, refusing invalid/conflicting/deleted groups, and converging
concurrent migrations and cancelled-call retries.

`scenarios.json` names the 105 Go scenarios selected by tracker #1290 and tenant dispatch plus 16 account-inbox scenarios for #470, one registration privacy scenario (AK-J03-C06), one fail-closed sign-in scenario (AK-J04-C06), three workload-renewal scenarios (AK-J35), six tenant-name scenarios (AK-J37, #471) and nine account-event consumer scenarios (AK-J38). The separate `auth-ui` suite requires nine J29 scenario IDs, exercised with the selected client methods in 18 browser/client cases; its result checker also requires the exact set of 18 executable case IDs. The required result checker rejects failures, skips, missing scenario passes, and duplicate scenario IDs; a passing nested branch cannot qualify a failed parent scenario.

Run the backend suite with `scripts/check.sh workflows`, or select a journey locally with `go test -run 'TestCriticalSessions' -v ./critical`. Set `AUTHKIT_TEST_DATABASE_URL` and `AUTHKIT_TEST_REDIS_URL` to disposable services. Each journey owns a PostgreSQL schema; no test skips because a service is missing. `scripts/check.sh contracts` retains compiler/vet, sqlc generation/validation, and released migration checks.

[http-methods.tsv](http-methods.tsv) maps all 171 logical HTTP operations: 75 selected functional bindings, 68 admission/privacy-only rows, and 28 deferred operations. It combines explicit Go assertions with the browser method semantic map; a wrapper invocation alone is not qualification. These are the selected initial contracts, not exhaustive combinations of permissions and errors.

The fixed route admission table checks selected protected contracts with missing, malformed, expired, revoked, and wrong-scope credentials. It comes from reviewed API contracts, not the running router. Optional features are mounted for their refusal probes. Successful state transitions belong to the named journeys and shipped TypeScript flows: denial probes alone do not qualify a feature's full functionality.

[go-methods.tsv](go-methods.tsv) maps the 92 selected root Go methods to their primary scenario and direct call evidence; 36 methods remain deferred. This does not count every SDK helper as a service operation.

The initial suite prioritizes credentials, permissions, tenant boundaries, recovery, token profiles, retained events, and account deletion. Full positive provider, passkey, device-key, OAuth federation/consent, directory synchronization, and presentation coverage remain expansion work. Runtime cases inside a journey are distinct from the 125 scenario count; neither count claims every possible input or schedule.

Time is controlled at existing clock and external timestamp boundaries. The deletion cutoff case pauses the actual database scan through a pgx driver hook, then ages its three imported fixture timestamps to one microsecond before, exactly at, and one microsecond after the cutoff obtained by the real worker. The hook changes no query or result; an exclusive-cutoff mutation must fail. Direct fixture updates only age a specific owned expiration/retention timestamp; assertions read public APIs. The cleanup convergence case uses small independently expired cohorts, not a maximum-batch load benchmark. Stateless token verification intentionally differs from live session and permission checks.

The published `authtest`, `auth/authtest`, and `userinfo/userinfotest` packages remain supported for downstream consumers. Their existing helpers are not counted as new AuthKit behavioral coverage. Old private harnesses with no remaining imports were removed.
