package engine

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/jackc/pgx/v5"
	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/internal/contact"
	"github.com/open-rails/authkit/internal/db"
	"github.com/open-rails/authkit/internal/errmodel"
	"github.com/open-rails/authkit/internal/ops"
)

// EnsureUserRole makes the account u names hold role in ref, under the
// system, and is idempotent on every boot. ops.InTx runs it in the host's
// transaction.
//
// u is an id, an email or a phone; a username proves nothing and is refused.
// With no account for the contact, one is created without credentials and
// with the contact unverified: only a proof of that contact can ever sign in,
// and that proof verifies it. An existing account is used when u is its id or
// the contact is verified on it; one that already holds role, the group's
// owner role, or a role covering role is left as it is (a re-run, including on
// the unverified account an earlier call created). Any other account is
// refused with ErrContactNotVerified: a pre-registered account is never
// adopted, and nothing here marks a contact verified.
func (s *Engine) EnsureUserRole(ctx context.Context, ref iam.GroupRef, u iam.UserRef, role iam.Role, opts ...ops.Option) (iam.User, error) {
	host, err := hostTx("EnsureUserRole", opts)
	if err != nil {
		return iam.User{}, err
	}
	key, value, err := ensureUserKey(u)
	if err != nil {
		return iam.User{}, err
	}
	var out iam.User
	err = s.withGroupMutationIn(ctx, iam.SystemIdentity(), host, ref, func(st *permissionGroupStore, g groupTarget) error {
		if !s.validRoleForPersona(s.groupSchemaOrDefault(), g.Persona, role) {
			return fmt.Errorf("role %q is not assignable in a %q group: %w", role, g.Persona, iam.ErrRoleNotAssignable)
		}
		if err := s.requireDefinedGroupRole(g.Persona, role); err != nil {
			return err
		}
		q := db.New(st.q)
		id, bound, err := lockEnsureUser(ctx, q, key, value)
		if err != nil {
			return err
		}
		created := id == ""
		if created {
			if key == iam.UserKeyID {
				return iam.ErrUserNotFound
			}
			acct := newAccount{Username: s.derivePasswordlessUsername(ctx, ensureUserChannel(key), value)}
			if key == iam.UserKeyEmail {
				acct.Email = value
			} else {
				acct.PhoneNumber = value
			}
			u, err := s.importUser(ctx, q, acct)
			if err != nil {
				return mapUserUniqueViolation(err)
			}
			id = u.ID
			if err := st.record(ctx, userEvent(iam.EventUserRegistered, id)); err != nil {
				return err
			}
		}
		subject := iam.UserSubject(id)
		current, err := st.directRole(ctx, g, subject)
		if err != nil {
			return err
		}
		held, err := s.roleHeld(ctx, st, g, current, role)
		if err != nil {
			return err
		}
		if !held {
			if !created && !bound {
				return errmodel.E(errmodel.CodeContactNotVerified, errmodel.WithDetails(errmodel.ContactProofRequired{
					Identifier: value, Channel: string(key), Reason: "contact_unproven",
				}))
			}
			if !current.IsZero() {
				if err := s.refuseOwnerLoss(ctx, st, g.ID, subject); err != nil {
					return err
				}
			}
			// A created account cannot be enrolled in MFA yet; its first
			// session must enroll when role requires it.
			if !created {
				if err := s.requireMFAForRoleAssignment(ctx, st.q, g.ID, g.Persona, subject, role); err != nil {
					return err
				}
			}
			if err := st.AssignRole(ctx, g.ID, subject, role); err != nil {
				return err
			}
		}
		out, err = userIn(ctx, st.q, id)
		return err
	})
	if err != nil {
		return iam.User{}, err
	}
	return out, nil
}

// ensureUserKey validates and normalizes u for EnsureUserRole.
func ensureUserKey(u iam.UserRef) (iam.UserKey, string, error) {
	value := u.Value()
	switch u.Key() {
	case iam.UserKeyID:
		if !isUUID(value) {
			return "", "", iam.ErrUserNotFound
		}
		return iam.UserKeyID, strings.ToLower(value), nil
	case iam.UserKeyEmail:
		if err := contact.ValidateEmail(value); err != nil {
			return "", "", err
		}
		return iam.UserKeyEmail, contact.NormalizeEmail(value), nil
	case iam.UserKeyPhone:
		if err := contact.ValidatePhone(value); err != nil {
			return "", "", err
		}
		return iam.UserKeyPhone, contact.NormalizePhone(value), nil
	case iam.UserKeyUsername:
		return "", "", errors.New("authkit: EnsureUserRole finds an account by id, email or phone; a username proves nothing")
	}
	return "", "", iam.ErrUserNotFound
}

func ensureUserChannel(key iam.UserKey) string {
	if key == iam.UserKeyEmail {
		return passwordlessChannelEmail
	}
	return passwordlessChannelSMS
}

// lockEnsureUser locks the live account key names. bound reports whether key
// proves who holds it: the id itself, or a verified contact. A deleted
// account is ErrUserNotFound: its contact cannot be reused while it exists.
func lockEnsureUser(ctx context.Context, q *db.Queries, key iam.UserKey, value string) (id string, bound bool, err error) {
	acct, err := lockBootstrapAccount(ctx, q, key, value)
	switch {
	case errors.Is(err, pgx.ErrNoRows):
		return "", false, nil
	case err != nil:
		return "", false, err
	case acct.Deleted:
		return "", false, fmt.Errorf("the account with %s %s is deleted: %w", key, value, iam.ErrUserNotFound)
	}
	return acct.ID, acct.Verified, nil
}

// keyedAccount is the account a key names; the BootstrapAccountBy* queries
// share its shape.
type keyedAccount = db.BootstrapAccountByIDForUpdateRow

// lockBootstrapAccount locks the account an id, email or phone names
// (pgx.ErrNoRows: none). Verified reports whether key proves who holds it.
func lockBootstrapAccount(ctx context.Context, q *db.Queries, key iam.UserKey, value string) (keyedAccount, error) {
	switch key {
	case iam.UserKeyID:
		return q.BootstrapAccountByIDForUpdate(ctx, value)
	case iam.UserKeyEmail:
		acct, err := q.BootstrapAccountByEmailForUpdate(ctx, value)
		return keyedAccount(acct), err
	default:
		acct, err := q.BootstrapAccountByPhoneForUpdate(ctx, value)
		return keyedAccount(acct), err
	}
}

// roleHeld reports whether current already gives what role would: the same
// role, the group's owner role, or a role whose grants cover role's.
func (s *Engine) roleHeld(ctx context.Context, st *permissionGroupStore, g groupTarget, current, role iam.Role) (bool, error) {
	switch {
	case current.IsZero():
		return false, nil
	case current == role, current.IsOwner():
		return true, nil
	}
	have, err := s.roleGrants(g.Persona, current)
	if errors.Is(err, iam.ErrRoleNotAssignable) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	want, err := s.roleGrants(g.Persona, role)
	if err != nil {
		return false, err
	}
	return grantsCoverAll(have, want), nil
}
