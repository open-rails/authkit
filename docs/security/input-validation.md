# Password hash and rate-limit input contracts

Password verification and host imports must reject malformed or excessive stored
work factors before running a KDF. Supported legacy credentials remain usable;
imports can mark an unsupported historical credential
`iam.HashAlgoLegacyResetRequired` and send the user through recovery.

Rate-limit thresholds and windows must be positive. Both bundled backends use
whole milliseconds, validate the same values at construction, and retain an
immutable copy of the configured policy. Cooldown is the minimum interval between
accepted requests and cannot exceed the retention window. To disable HTTP rate
limiting for a test, set `HTTPConfig.DisableRateLimiting` rather than a zero
threshold.

Supported Argon2id hashes use version 19, exact `m=<decimal>,t=<decimal>,p=<decimal>`
parameters, and canonical unpadded Base64. The encoded hash is at most 256 bytes;
parallelism is 1–16, memory is 8 × parallelism through 262144 KiB, iterations are
1–10, and memory × iterations is at most 1048576 KiB. Salt length is 8–64 bytes;
digest length is 16–64 bytes. Bcrypt accepts exactly 60-byte `$2a$`, `$2b$`, or
`$2y$` hashes with costs 4–14. Algorithm names are required, including for imported bcrypt hashes.

AuthKit's generated Argon2id defaults are unchanged (65536 KiB, one iteration,
one thread, 16-byte salt, 32-byte digest). Common PHP Argon2id settings and bcrypt
costs 10–12 fit this policy. This is a supported-format contract, not an inventory
of deployed historical hashes. `ImportUsers` and `UpdateUser` reject unsafe
values per row without running a KDF; they never silently convert them to a
usable credential. Stored corrupt/unsupported hashes also
fail safely at verification and enter the existing `password_reset_required`
login outcome without rewriting the stored credential.

Both limiters reject nonpositive limits, values above 2^53−1 (Lua's exact
integer range), nonpositive or fractional-millisecond windows, and negative,
fractional-millisecond or over-window cooldowns, so `authkit.New` fails on a bad
`HTTPConfig.RateLimits` override. Redis keeps state with a millisecond TTL.
