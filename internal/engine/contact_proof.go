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

func contactVerificationRequired(identifier, channel string) error {
	return errmodel.E(errmodel.CodeVerificationRequired, errmodel.WithDetails(errmodel.ContactProofRequired{
		Identifier: identifier, Channel: channel, Reason: "contact_unproven",
	}))
}

// refuseProofBesideUnproven refuses a contact change on channel (email or
// sms) that would prove a new address while the account's other address
// stays unproven (ak#417). On an account with no proven address, a change may
// only replace the unproven address: its first proof is then always of, or in
// place of, the address it was registered with, and retires every credential
// that predates it. Proving a second address instead would make the account
// proven, so the real owner's later proof of the first would leave the
// squatter's credentials, and the squatter's verified address, in place.
func refuseProofBesideUnproven(u *db.User, channel string) error {
	if u == nil || u.Email != nil && u.EmailVerified || u.PhoneNumber != nil && u.PhoneVerified {
		return nil
	}
	switch {
	case channel != passwordlessChannelEmail && u.Email != nil:
		return contactVerificationRequired(*u.Email, "email")
	case channel != passwordlessChannelSMS && u.PhoneNumber != nil:
		return contactVerificationRequired(*u.PhoneNumber, "phone")
	}
	return nil
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
		return contactVerificationRequired(st.Identifier, st.Channel)
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
// account's addresses (or, for a contact change, replaces its unproven one),
// before the address is marked verified. When no address was proven yet, whoever created the account's credentials was never shown to
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
		q.MFASettingsDelete,
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
