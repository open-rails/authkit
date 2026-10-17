-- Retain existing hashed recovery sets, including passkey-only accounts.
-- Detached historical sets must never become valid when a later key is added.
DELETE FROM mfa_settings s
WHERE NOT EXISTS (SELECT 1 FROM mfa_factors f WHERE f.user_id=s.user_id)
  AND NOT EXISTS (SELECT 1 FROM user_passkeys p WHERE p.user_id=s.user_id);
COMMENT ON TABLE mfa_settings IS 'Account recovery-code hashes; retained while a code factor or passkey exists. This row does not enable MFA.';
