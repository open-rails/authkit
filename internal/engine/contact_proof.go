package engine

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/internal/db"
	"github.com/open-rails/authkit/internal/errmodel"
	"github.com/open-rails/authkit/internal/secret"
	"github.com/open-rails/helpers/auth"
)

// Contact ownership (ak#393). An account whose only addresses are unproven was
// created by someone who has not shown they control them: anyone can register
// victim@example.com, or have another system confirm it for them and import
// it. Such an account may sign in, but it cannot add login methods, and the
// first proof of one of its addresses retires every credential and every
// other address created before that proof, so a pre-registration can never
// leave the real owner's account with a backdoor.

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

// proof names what a proof covers: the addresses, and whether the prover
// also proved the account's password in the same sign-in.
type proof struct{ email, phone, password bool }

// proofOn is a proof of the account's address on channel (email or sms).
func proofOn(channel string) proof {
	return proof{email: channel == passwordlessChannelEmail, phone: channel == passwordlessChannelSMS}
}

// retirePreProofCredentials runs in the transaction that proves one of the
// account's addresses (or, for a contact change, replaces its unproven one),
// before the address is marked verified, on behalf of a. When no address was
// proven yet, whoever created the account's credentials was never shown to
// control it, so every credential and session goes: the addresses p does not cover,
// provider links (including Solana wallets), passkeys, device keys, 2FA
// factors and backup codes, the API keys, invite links and account invitations
// the account issued, the applications it registered (they keep no
// registrar), and refresh sessions on every account issuer.
//
// keepSessionID is the authenticated session presenting the proof, if any. It
// survives. The password survives only when the prover demonstrably holds it
// too: that live session proved it, or p.password (a sign-in proved it and
// handed the code's confirmation its password proof). A proof from a fresh
// device, a reset or an email/SMS login code says nothing about who set the
// password, so it is deleted (a reset replaces it anyway).
func (s *Engine) retirePreProofCredentials(ctx context.Context, tx pgx.Tx, a auth.Identity, userID string, p proof, keepSessionID *string) ([]revokedSession, error) {
	st, err := contactStateForUpdate(ctx, tx, userID)
	if err != nil || !st.Unproven {
		return nil, err
	}
	q := s.qtx(tx)
	if err := s.dropUnprovenContacts(ctx, tx, a, userID, p); err != nil {
		return nil, err
	}
	keepPassword := p.password
	if keepSessionID != nil && *keepSessionID != "" {
		pwd, err := q.SessionProvedPassword(ctx, db.SessionProvedPasswordParams{SessionID: *keepSessionID, UserID: userID})
		switch {
		case errors.Is(err, pgx.ErrNoRows):
			keepSessionID = nil
		case err != nil:
			return nil, err
		default:
			keepPassword = keepPassword || pwd
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

// dropUnprovenContacts removes the account's addresses that the first proof
// does not cover. Nobody has shown they control them, and each would still
// sign in to or recover the account (a reset or a login code to it).
func (s *Engine) dropUnprovenContacts(ctx context.Context, tx pgx.Tx, a auth.Identity, userID string, p proof) error {
	if p.email && p.phone {
		return nil
	}
	before, err := readAccountIdentity(ctx, tx, userID)
	if err != nil {
		return err
	}
	q := s.qtx(tx)
	if !p.email {
		if err := q.UserSetEmail(ctx, db.UserSetEmailParams{ID: userID}); err != nil {
			return err
		}
	}
	if !p.phone {
		if err := q.UserSetPhone(ctx, db.UserSetPhoneParams{ID: userID}); err != nil {
			return err
		}
	}
	changes, err := identityChanges(ctx, tx, userID, before)
	if err != nil {
		return err
	}
	return s.emitEvents(ctx, tx, a, changes...)
}

// A password sign-in parked at a code (verificationGate) proved the password,
// but not the address. Its password proof is a single-use token for that
// account at its credential version: the code's confirmation presents it, and
// the address's proof then keeps the password. Whoever planted a password
// can't read the code, and whoever reads the code doesn't hold the token.
type passwordProofData struct {
	UserID  string `json:"user_id"`
	Version int64  `json:"version"`
}

// issuePasswordProof records that a sign-in just proved userID's password and
// returns its token, valid for ttl.
func (s *Engine) issuePasswordProof(ctx context.Context, userID string, ttl time.Duration) (string, error) {
	v, err := s.q.UserCredentialVersion(ctx, userID)
	if err != nil {
		return "", err
	}
	token := secret.Token(32)
	return token, s.ephemSetJSON(ctx, keyPasswordProof+secret.Hash(token), passwordProofData{UserID: userID, Version: v.CredentialVersion}, ttl)
}

// spendPasswordProof consumes token and returns the credential version it
// proved userID's password at, or 0: no token, or one spent, expired or
// issued for another account.
func (s *Engine) spendPasswordProof(ctx context.Context, token, userID string) (int64, error) {
	if token == "" {
		return 0, nil
	}
	var d passwordProofData
	ok, err := s.ephemConsumeJSON(ctx, keyPasswordProof+secret.Hash(token), &d)
	if err != nil || !ok || d.UserID != userID {
		return 0, err
	}
	return d.Version, nil
}
