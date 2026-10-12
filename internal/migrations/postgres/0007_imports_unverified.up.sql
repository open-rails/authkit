-- An imported address is unverified, like any other: the account proves it at
-- its first sign-in when registration requires verification.
SET LOCAL lock_timeout = '10s';

ALTER TABLE users DROP COLUMN verified_elsewhere;
