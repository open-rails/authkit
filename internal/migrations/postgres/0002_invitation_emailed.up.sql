-- An email invitation records when its code was emailed: it then went to the
-- invited address alone, so registering that address with it proves it.
SET LOCAL lock_timeout = '10s';
SET LOCAL statement_timeout = '300s';

ALTER TABLE account_registration_invites ADD COLUMN emailed_at timestamptz;
COMMENT ON COLUMN account_registration_invites.emailed_at IS 'When the code was emailed to email, which then alone held it: registering email with it proves the address. NULL = not emailed; the inviter was given it to share.';
