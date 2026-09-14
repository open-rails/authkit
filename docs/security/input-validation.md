# Password hash and rate-limit input contracts

Password verification and host imports must reject malformed or excessive stored
work factors before running a KDF. Supported legacy credentials remain usable;
operators can explicitly mark unsupported historical credentials
`legacy_reset_required` and send the user through recovery.

Rate-limit thresholds and windows must be positive. Both bundled backends use
whole milliseconds, validate the same values at construction, and retain an
immutable copy of the configured policy. Cooldown is the minimum interval between
accepted requests and cannot exceed the retention window. To disable HTTP rate
limiting for a test, use the explicit HTTP option rather than a zero threshold.
