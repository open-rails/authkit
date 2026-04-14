-- Seed required global admin role for bootstrap and admin gate flows.

SET lock_timeout = '10s';
SET statement_timeout = '300s';

INSERT INTO profiles.roles (name, slug, description)
VALUES ('Admin', 'admin', 'Global platform administrator')
ON CONFLICT (slug) DO NOTHING;
