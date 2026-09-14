# Password hash and rate-limit input contracts

Password verification and host imports must reject malformed or excessive stored
work factors before running a KDF. Supported legacy credentials remain usable;
operators can explicitly mark unsupported historical credentials
`legacy-reset-required` and send the user through recovery.

Rate-limit thresholds and windows must be positive. Both bundled backends use
whole milliseconds, validate the same values at construction, and retain an
immutable copy of the configured policy. Cooldown is the minimum interval between
accepted requests and cannot exceed the retention window. To disable HTTP rate
limiting for a test, use the explicit HTTP option rather than a zero threshold.

Supported Argon2id hashes use version 19, exact `m=<decimal>,t=<decimal>,p=<decimal>`
parameters, and canonical unpadded Base64. The encoded hash is at most 256 bytes;
parallelism is 1–16, memory is 8 × parallelism through 262144 KiB, iterations are
1–10, and memory × iterations is at most 1048576 KiB. Salt length is 8–64 bytes;
digest length is 16–64 bytes. Bcrypt accepts exactly 60-byte `$2a$`, `$2b$`, or
`$2y$` hashes with costs 4–14. Empty algorithm names only support legacy bcrypt.

AuthKit's generated Argon2id defaults are unchanged (65536 KiB, one iteration,
one thread, 16-byte salt, 32-byte digest). Common PHP Argon2id settings and bcrypt
costs 10–12 fit this policy. This is a supported-format contract, not an inventory
of deployed historical hashes. Import rejects unsafe values per row; it never
silently converts them to a usable credential. `password.ValidateHash` supports
import preflight without running a KDF. Stored corrupt/unsupported hashes also
fail safely at verification.

`memorylimiter.New` and `redislimiter.New` now return `(*Limiter, error)`; callers
must handle construction errors. Both reject nonpositive limits, values above
2^53−1 (Lua's exact integer range), nonpositive/fractional-millisecond windows,
and negative/fractional-millisecond or over-window cooldowns. The memory bucket
cap must be positive. Redis requires a client and retains state with a
millisecond TTL. Empty policy maps keep the same built-in fallback. HTTP `New`
already returns errors and propagates these checks for ordinary overrides.

Test coverage is consolidated around the import/recovery workflow and one shared
real memory/Redis policy workflow (threshold, cooldown, overlapping window,
independent keys/buckets, copied configuration, TTL). These replace separate
backend threshold/cooldown tests and the old memory zero-limit exception test.
Malformed PHC and supported legacy roundtrips replace the older shallow
malformed/bcrypt-prefix tests. Small decode-only fuzz, exact-boundary retention,
concurrent-admission, cleanup and backend-failure checks remain independent
because a sequential happy path cannot establish those properties.
