-- Two trust models per tenant issuer, mutually exclusive (#465 / tensorhub):
--   mode='jwks'   — preferred: keys fetched+refreshed from jwks_uri; rotation
--                   is publishing a new kid at the same URL (no API call).
--   mode='static' — authorized_keys-style: a human-managed list of public key
--                   PEMs for services without a JWKS endpoint; manual rotation
--                   by design.
-- Never both: the XOR check rejects a row carrying both a jwks_uri and a key
-- list, so an issuer's trust source is always unambiguous.

ALTER TABLE profiles.tenant_issuers
  ADD COLUMN IF NOT EXISTS mode text NOT NULL DEFAULT 'jwks',
  ADD COLUMN IF NOT EXISTS public_keys jsonb;

ALTER TABLE profiles.tenant_issuers
  ADD CONSTRAINT tenant_issuers_mode_check
    CHECK (mode IN ('jwks', 'static')),
  ADD CONSTRAINT tenant_issuers_trust_source_xor
    CHECK (
      (mode = 'jwks'   AND jwks_uri <> '' AND public_keys IS NULL)
      OR
      (mode = 'static' AND jwks_uri = '' AND public_keys IS NOT NULL
         AND jsonb_typeof(public_keys) = 'array' AND jsonb_array_length(public_keys) > 0)
    );

COMMENT ON COLUMN profiles.tenant_issuers.mode IS 'Trust source: jwks (fetch from jwks_uri) XOR static (human-managed public_keys list).';
COMMENT ON COLUMN profiles.tenant_issuers.public_keys IS 'static mode only: JSON array of {kid, public_key_pem} entries, edited by humans like an authorized_keys file.';
