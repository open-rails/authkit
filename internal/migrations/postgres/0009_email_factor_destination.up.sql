-- parent: 8 sha256:29b8933a9d118c0058ac964e78c4af8f5d825d36c47f3e37e830a0126feb2e9e
-- An email factor is bound to the address its setup code proved, as an SMS
-- factor is to its phone: changing the account's email never redirects its
-- codes. Existing factors are pinned to the address they were sending to.
ALTER TABLE mfa_factors ADD COLUMN email text;
UPDATE mfa_factors f SET email = u.email FROM users u WHERE u.id = f.user_id AND f.method = 'email';
