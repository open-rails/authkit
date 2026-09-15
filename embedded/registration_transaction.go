package embedded

import (
	"context"
	"strings"

	authkit "github.com/open-rails/authkit"
	"github.com/open-rails/authkit/internal/db"
)

// accountRegistration is the one database operation behind public signup. The
// caller has verified any contact/provider proof and supplies no existing user.
type accountRegistration struct {
	User        ImportUserInput
	Language    string
	InviteToken string
	Provider    *ExternalIdentity
}

type registeredAccount struct {
	ID      string
	Version int64
}

func (s *Client) registerAccount(ctx context.Context, in accountRegistration) (registeredAccount, error) {
	if err := s.requirePG(); err != nil {
		return registeredAccount{}, err
	}
	tx, err := s.pg.Begin(ctx)
	if err != nil {
		return registeredAccount{}, err
	}
	defer tx.Rollback(ctx)
	invite, err := s.lockRegistrationInvite(ctx, tx, in.InviteToken)
	if err != nil {
		return registeredAccount{}, err
	}
	q := s.qtx(tx)
	user, err := s.importUser(ctx, q, in.User)
	if err != nil {
		return registeredAccount{}, mapUserUniqueViolation(err)
	}
	if err := s.admitName(ctx, authkit.NameAdmissionRequest{OwnerKind: "user", OwnerID: user.ID, RequestedName: in.User.Username, Operation: authkit.NameCreate}); err != nil {
		return registeredAccount{}, err
	}
	if in.User.PasswordHash != "" {
		if err := q.UserPasswordInsert(ctx, db.UserPasswordInsertParams{UserID: user.ID, PasswordHash: in.User.PasswordHash}); err != nil {
			return registeredAccount{}, err
		}
	}
	if in.Language != "" {
		if err := q.UserSetPreferredLanguage(ctx, db.UserSetPreferredLanguageParams{ID: user.ID, PreferredLanguage: nullable(in.Language)}); err != nil {
			return registeredAccount{}, err
		}
	}
	if id := in.Provider; id != nil {
		if _, err := linkProviderByIssuer(ctx, q, user.ID, id.Issuer, id.Provider, id.Subject, nullable(strings.TrimSpace(id.Email))); err != nil {
			return registeredAccount{}, err
		}
		if id.PreferredUsername != "" {
			if err := q.UserProviderSetUsername(ctx, db.UserProviderSetUsernameParams{UserID: user.ID, Issuer: id.Issuer, Subject: id.Subject, Username: id.PreferredUsername}); err != nil {
				return registeredAccount{}, err
			}
		}
	}
	if err := s.applyRegistrationInvite(ctx, tx, invite, user.ID); err != nil {
		return registeredAccount{}, err
	}
	version, err := q.UserCredentialVersion(ctx, user.ID)
	if err != nil {
		return registeredAccount{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return registeredAccount{}, err
	}
	return registeredAccount{ID: user.ID, Version: version.CredentialVersion}, nil
}
