-- parent: 1 sha256:b694d4995d77dbab392afb195ed055d58195fe73b7f665d85a44f30045fa0005
-- The user directory's search (ListUsers). Username, email and phone match by
-- substring through trigram indexes; the columns are indexed as text, so the
-- search casts citext to text (citext's own ILIKE is no trigram operator). A
-- linked sign-in matches exactly on its subject (a wallet address, a
-- provider's user id), provider email or provider username.
SET LOCAL lock_timeout = '10s';

CREATE EXTENSION IF NOT EXISTS pg_trgm WITH SCHEMA public;

CREATE INDEX users_username_trgm_idx
  ON users USING gin (username public.gin_trgm_ops);
CREATE INDEX users_email_trgm_idx
  ON users USING gin (email public.gin_trgm_ops);
CREATE INDEX users_phone_number_trgm_idx
  ON users USING gin (phone_number public.gin_trgm_ops);

CREATE INDEX user_providers_subject_idx
  ON user_providers (subject);
CREATE INDEX user_providers_email_lower_idx
  ON user_providers (lower(email_at_provider));
CREATE INDEX user_providers_username_lower_idx
  ON user_providers (lower(profile->>'username'));
