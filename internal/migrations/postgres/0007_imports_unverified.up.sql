-- parent: 6 sha256:d0a70ce78b1a793becc8f2c4cb638dbffbfe121064612f5fe40b88e35a7aad9b
-- An imported address is unverified, like any other: the account proves it at
-- its first sign-in when registration requires verification.
SET LOCAL lock_timeout = '10s';

ALTER TABLE users DROP COLUMN verified_elsewhere;
