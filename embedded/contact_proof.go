package embedded

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5"
	authkit "github.com/open-rails/authkit"
	"github.com/open-rails/authkit/internal/db"
)

// Contact ownership (ak#393). An account whose only addresses are unproven was
// created by someone who has not shown they control them: anyone can register
// victim@example.com. Such an account may sign in, but it cannot add login
// methods, and the first proof of one of its addresses retires every
// credential created before that proof, so a pre-registration can never leave
// the real owner's account with a backdoor.

type contactState struct {
	unproven   bool
	identifier string
	channel    string
}

func readContactState(ctx context.Context, q db.DBTX, userID string, lock bool) (contactState, error) {
	sql := `SELECT (email IS NOT NULL OR phone_number IS NOT NULL)
	           AND NOT ((email IS NOT NULL AND email_verified) OR (phone_number IS NOT NULL AND phone_verified)),
	         COALESCE(email::text, phone_number, ''), CASE WHEN email IS NOT NULL THEN 'email' ELSE 'phone' END
	    FROM users WHERE id = $1::uuid`
	if lock {
		sql += ` FOR UPDATE`
	}
	var st contactState
	err := q.QueryRow(ctx, sql, userID).Scan(&st.unproven, &st.identifier, &st.channel)
	if errors.Is(err, pgx.ErrNoRows) {
		return st, ErrUserNotFound
	}
	return st, err
}

func contactVerificationRequired(st contactState) error {
	return authkit.E(authkit.CodeVerificationRequired, authkit.WithMetadata(map[string]any{
		"identifier": st.identifier,
		"channel":    st.channel,
		"reason":     "contact_unproven",
	}))
}

// requireProvenContactOn refuses to add a login method while the account's
// addresses are all unproven. Accounts with no address have nothing a
// pre-registration could claim and are unaffected.
func requireProvenContactOn(ctx context.Context, q db.DBTX, userID string) error {
	st, err := readContactState(ctx, q, userID, false)
	if err != nil {
		return err
	}
	if st.unproven {
		return contactVerificationRequired(st)
	}
	return nil
}

// RequireProvenContact is the pre-flight form of the login-method gate.
func (s *engine) RequireProvenContact(ctx context.Context, userID string) error {
	if err := s.requirePG(); err != nil {
		return err
	}
	return requireProvenContactOn(ctx, s.pg, userID)
}

// retirePreProofCredentials runs in the transaction that proves one of the
// account's addresses, before the address is marked verified. When no address
// was proven yet, whoever created the account's credentials was never shown to
// control it, so every credential and session goes: provider links (including
// Solana wallets), passkeys, device keys, 2FA factors and backup codes, API
// keys the account created, and refresh sessions on every account issuer.
//
// keepSessionID is the authenticated session presenting the proof, if any. It
// survives, and the password survives only when that live session itself
// proved the password: then the prover demonstrably holds both. A proof from a
// fresh device, a reset or an email/SMS login code says nothing about who set
// the password, so it is deleted (a reset replaces it anyway).
func (s *engine) retirePreProofCredentials(ctx context.Context, tx pgx.Tx, userID string, keepSessionID *string) ([]revokedSession, error) {
	st, err := readContactState(ctx, tx, userID, true)
	if err != nil || !st.unproven {
		return nil, err
	}
	keepPassword := false
	if keepSessionID != nil && *keepSessionID != "" {
		var pwd bool
		err := tx.QueryRow(ctx, `SELECT 'pwd' = ANY(auth_methods) FROM refresh_sessions
			WHERE id = $1::uuid AND user_id = $2::uuid AND revoked_at IS NULL AND (expires_at IS NULL OR expires_at > now())`,
			*keepSessionID, userID).Scan(&pwd)
		switch {
		case errors.Is(err, pgx.ErrNoRows):
			keepSessionID = nil
		case err != nil:
			return nil, err
		default:
			keepPassword = pwd
		}
	} else {
		keepSessionID = nil
	}
	statements := []string{
		`DELETE FROM user_providers WHERE user_id = $1::uuid`,
		`UPDATE user_passkeys SET deleted_at = now() WHERE user_id = $1::uuid AND deleted_at IS NULL`,
		`UPDATE user_device_keys SET revoked_at = now() WHERE user_id = $1::uuid AND revoked_at IS NULL`,
		`DELETE FROM mfa_factors WHERE user_id = $1::uuid`,
		`UPDATE mfa_settings SET enabled = false, backup_codes = NULL, updated_at = now() WHERE user_id = $1::uuid`,
		`UPDATE api_keys SET revoked_at = now() WHERE created_by = $1::uuid AND revoked_at IS NULL`,
	}
	if !keepPassword {
		statements = append(statements, `DELETE FROM user_passwords WHERE user_id = $1::uuid`)
	}
	for _, stmt := range statements {
		if _, err := tx.Exec(ctx, stmt, userID); err != nil {
			return nil, err
		}
	}
	return revokeSessionsTx(ctx, s.qtx(tx), userID, s.accountIssuers(), keepSessionID)
}
