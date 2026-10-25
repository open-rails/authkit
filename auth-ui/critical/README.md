# AuthKit critical browser/client replacement

`pnpm test` builds the current package once, typechecks the browser harness, starts disposable PostgreSQL and actual AuthKit runtimes, runs Chromium, then checks the structured report. The three fixtures use required verification, real low rate limits, and optional verification; captured email/SMS are external delivery boundaries. Runtime authentication, authorization, persistence and queues are real.

The suite has 18 real-service tests: nine required J29 scenario IDs (C04 has two independently named callback variants), plus thin public-client contract journeys. All 86 selected callable client methods must execute in passing tests. `methods.tsv` records the semantic assertion owner; invocation alone is not proof. The transparent fixture proxy only records method names, preserves real methods/results, and never substitutes API responses. Native component calls are observed through the same public client.

Each executable case has a required AK-UI ID in coverage.json. The gate checks that exact set as well as the logical scenarios and method bindings, so removing a case cannot be hidden by another case invoking the same methods. No skipped/expected-failure/empty run passes the result check. For local development only, run focused cases with `pnpm exec playwright test --grep ...`; this does not claim full qualification. Required CI calls `pnpm test` without a focus filter.

`getSnapshot()` intentionally includes the access token; refresh secrets and private keys must not leak into it. GET/me deliberately permits a stateless self/tombstone read; PATCH/me requires a current live session. Actual HTTP cache and client retry backoff are respected, not interpreted as failures. The contact-proof replacement-sign-in scenario preserves the generation fence and requires a new explicit mutation.

The old mocked/unit/browser corpus, visual snapshots, unused stub helpers and jsdom/Vitest dependencies are removed. Build/type/lint/generation/artifact checks remain. This child branch merges into the parent AuthKit replacement candidate; public Go test-support APIs remain compatible.

The native notification widgets use AuthKit directly. AK-UI-18 exercises cursor pagination, shared bell invalidation, keyboard popover handling, read/archive persistence, unseen withdrawal/stale replay, later reopen and identity switching. No ContentKit client or provider is present.
