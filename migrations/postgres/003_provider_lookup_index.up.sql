-- Provider-link lookup index (from the internal/db/querytest plan audit).
--
-- ProviderLinkBySlug filters by (provider_slug, subject) but no index led with
-- those columns, so it leaned on a PG18 skip scan over the (issuer, subject)
-- unique index whose cost grows with the number of distinct issuers. Index the
-- pair directly so the social-login lookup is a point probe regardless of how
-- many issuers exist.

CREATE INDEX IF NOT EXISTS user_providers_slug_subject_idx
  ON profiles.user_providers (provider_slug, subject);
