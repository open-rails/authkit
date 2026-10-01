-- parent: 4 sha256:bfb28b0042a789f0b47a877668ff48b2f4fd5862c600e8e22c8bcdf927b0aeaa
-- An imported verification is not proof. ImportUsers stores every address
-- unverified, and a verified flag the source system set becomes
-- verified_elsewhere: the account signs in without proving its address first,
-- but is unproven until it does.
SET LOCAL lock_timeout = '10s';

ALTER TABLE users ADD COLUMN verified_elsewhere boolean NOT NULL DEFAULT false;
COMMENT ON COLUMN users.verified_elsewhere IS 'An import said another system verified an address: the account signs in before proving one';
