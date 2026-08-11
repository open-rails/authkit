-- ak#273 (GitHub open-rails/authkit#69): the rename-history CHECK contradicted
-- the username validator, so a legal account could never be renamed.
--
-- `from_slug` is the renaming user's OWN previous username, lowercased and
-- otherwise unaltered (internal/authcore/users.go, updateUsernameImpl).
-- ValidateUsername admits `[A-Za-z][A-Za-z0-9_]{3,29}` and validateImportUsername
-- additionally admits `-` up to 64 bytes, but the 0001 predicate accepted neither
-- `_` nor a name longer than 63 bytes. A user named `it_abc123` therefore produced
-- a from_slug its own database rejected, and because that INSERT shares the rename
-- transaction the write that would escape the state is the one that fails.
--
-- The constraint now FOLLOWS the validators rather than contradicting them. It
-- still enforces what makes a from_slug a usable published alias — lowercase,
-- bounded, and free of whitespace, `@`, `.`, `/` — and drops only the
-- hyphen-only charset no validator ever produced. The new predicate is a strict
-- SUPERSET of the 0001 one, so every existing row satisfies it and the
-- revalidating ADD CONSTRAINT cannot fail on a live database.
ALTER TABLE profiles.user_renames
  DROP CONSTRAINT IF EXISTS user_renames_from_slug_format_chk;

ALTER TABLE profiles.user_renames
  ADD CONSTRAINT user_renames_from_slug_format_chk CHECK (
    from_slug = lower(from_slug)
    AND from_slug ~ '^[a-z0-9][a-z0-9_-]{0,63}$'
  );

COMMENT ON COLUMN profiles.user_renames.from_slug IS
  'The user''s previous username, lowercased and never slugified — the alias GET /me publishes as user_aliases. Charset follows authcore.ValidateUsername / validateImportUsername (ak#273).';
