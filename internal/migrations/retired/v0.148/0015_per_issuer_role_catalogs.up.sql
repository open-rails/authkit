-- parent: 14 sha256:171ebced2e2f931c664b3181d37059a21334f6b76fccf5479ce9e89462b90176
-- Apps sharing an account store (Token.AccountIssuers) share membership, and
-- each declares its own role catalog. A credential records the app that issued
-- it; only that app's catalog judges it. NULL predates this: every app judges
-- it. A store one app alone ever bound is that app's.
ALTER TABLE api_keys ADD COLUMN catalog_issuer text;
ALTER TABLE group_invite_links ADD COLUMN catalog_issuer text;
ALTER TABLE account_registration_invites ADD COLUMN catalog_issuer text;
ALTER TABLE remote_applications ADD COLUMN catalog_issuer text;
UPDATE api_keys SET catalog_issuer = (SELECT min(issuer) FROM account_delivery_fleets)
WHERE (SELECT count(*) FROM account_delivery_fleets) = 1;
UPDATE group_invite_links SET catalog_issuer = (SELECT min(issuer) FROM account_delivery_fleets)
WHERE (SELECT count(*) FROM account_delivery_fleets) = 1;
UPDATE account_registration_invites SET catalog_issuer = (SELECT min(issuer) FROM account_delivery_fleets)
WHERE (SELECT count(*) FROM account_delivery_fleets) = 1;
UPDATE remote_applications SET catalog_issuer = (SELECT min(issuer) FROM account_delivery_fleets)
WHERE (SELECT count(*) FROM account_delivery_fleets) = 1;
COMMENT ON COLUMN api_keys.catalog_issuer IS 'The Token.Issuer of the app that issued the key; only its role catalog judges it. NULL = every app does.';
COMMENT ON COLUMN group_invite_links.catalog_issuer IS 'The Token.Issuer of the app that issued the link; only its role catalog judges it. NULL = every app does.';
COMMENT ON COLUMN account_registration_invites.catalog_issuer IS 'The Token.Issuer of the app that issued the invite; only its role catalog judges it. NULL = every app does.';
COMMENT ON COLUMN remote_applications.catalog_issuer IS 'The Token.Issuer of the app its registrar registered it through; only its role catalog judges the application''s roles. NULL = every app does.';

-- Each app's role catalog as its credential sweep last reconciled it. An app
-- without a row sweeps its credentials at its next boot.
DROP TABLE role_catalog_state;
CREATE TABLE role_catalogs (
  issuer text PRIMARY KEY,
  fingerprint text NOT NULL,
  roles text[] NOT NULL,
  swept_at timestamptz NOT NULL DEFAULT now()
);
COMMENT ON COLUMN role_catalogs.roles IS 'The persona:role names the catalog declares; no other app counts them as drift.';
