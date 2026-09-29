package engine

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5"
	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/internal/db"
	"github.com/open-rails/authkit/internal/errmodel"
)

// Contact ownership (ak#393). An account whose only addresses are unproven was
// created by someone who has not shown they control them: anyone can register
// victim@example.com. Such an account may sign in, but it cannot add login
// methods, and the first proof of one of its addresses retires every
// credential created before that proof, so a pre-registration can never leave
// the real owner's account with a backdoor.

// contactState reads whether the account's addresses are all unproven, and
// the address to prove.
func contactState(ctx context.Context, q db.DBTX, userID string) (db.ContactStateRow, error) {
	st, err := db.New(q).ContactState(ctx, userID)
	if errors.Is(err, pgx.ErrNoRows) {
		return st, iam.ErrUserNotFound
	}
	return st, err
}

// contactStateForUpdate is contactState that also locks the account row.
func contactStateForUpdate(ctx context.Context, q db.DBTX, userID string) (db.ContactStateRow, error) {
	st, err := db.New(q).ContactStateForUpdate(ctx, userID)
	if errors.Is(err, pgx.ErrNoRows) {
		return db.ContactStateRow(st), iam.ErrUserNotFound
	}
	return db.ContactStateRow(st), err
}

func contactVerificationRequired(st db.ContactStateRow) error {
	return errmodel.E(errmodel.CodeVerificationRequired, errmodel.WithMetadata(map[string]any{
		"identifier": st.Identifier,
		"channel":    st.Channel,
		"reason":     "contact_unproven",
	}))
}

// requireProvenContactOn refuses to add a login method while the account's
// addresses are all unproven. Accounts with no address have nothing a
// pre-registration could claim and are unaffected.
func requireProvenContactOn(ctx context.Context, q db.DBTX, userID string) error {
	st, err := contactState(ctx, q, userID)
	if err != nil {
		return err
	}
	if st.Unproven {
		return contactVerificationRequired(st)
	}
	return nil
}

// RequireProvenContact is the pre-flight form of the login-method gate.
func (s *Engine) RequireProvenContact(ctx context.Context, userID string) error {
	if err := s.requirePG(); err != nil {
		return err
	}
	return requireProvenContactOn(ctx, s.pg, userID)
}

// retirePreProofCredentials runs in the transaction that proves one of the
// account's addresses, before the address is marked verified. When no address
// was proven yet, whoever created the account's credentials was never shown to
// control it, so every credential and session goes: provider links (including
// Solana wallets), passkeys, device keys, 2FA factors and backup codes, the API
// keys, invite links and account invitations the account issued, the
// applications it registered (they keep no registrar), and refresh sessions on
// every account issuer.
//
// keepSessionID is the authenticated session presenting the proof, if any. It
// survives, and the password survives only when that live session itself
// proved the password: then the prover demonstrably holds both. A proof from a
// fresh device, a reset or an email/SMS login code says nothing about who set
// the password, so it is deleted (a reset replaces it anyway).
func (s *Engine) retirePreProofCredentials(ctx context.Context, tx pgx.Tx, userID string, keepSessionID *string) ([]revokedSession, error) {
	st, err := contactStateForUpdate(ctx, tx, userID)
	if err != nil || !st.Unproven {
		return nil, err
	}
	q := s.qtx(tx)
	keepPassword := false
	if keepSessionID != nil && *keepSessionID != "" {
		pwd, err := q.SessionProvedPassword(ctx, db.SessionProvedPasswordParams{SessionID: *keepSessionID, UserID: userID})
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
	retire := []func(context.Context, string) error{
		q.UserProvidersDeleteByUser,
		q.PasskeysDeleteByUser,
		func(ctx context.Context, userID string) error {
			_, err := q.DeviceKeysRevokeAllExcept(ctx, db.DeviceKeysRevokeAllExceptParams{UserID: userID})
			return err
		},
		q.MFADeleteAllFactors,
		q.MFAResetSettings,
		q.APIKeysRevokeCreatedBy,
		q.InviteLinksRevokeInvitedBy,
		q.AccountInvitesRevokeInvitedBy,
		q.RemoteApplicationsClearRegistrar,
	}
	if !keepPassword {
		retire = append(retire, q.UserPasswordDelete)
	}
	for _, step := range retire {
		if err := step(ctx, userID); err != nil {
			return nil, err
		}
	}
	return revokeSessionsTx(ctx, q, userID, s.accountIssuers(), keepSessionID)
}
