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
)

// EnsureUserRole makes the account u names hold role in ref, under the
// operator, and is idempotent on every boot.
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
func (s *Engine) EnsureUserRole(ctx context.Context, a iam.Actor, ref iam.GroupRef, u iam.UserRef, role iam.Role) (iam.User, error) {
	if err := requireOperator(a); err != nil {
		return iam.User{}, err
	}
	role = iam.Role(strings.TrimSpace(string(role)))
	key, value, err := ensureUserKey(u)
	if err != nil {
		return iam.User{}, err
	}
	var outID string
	err = s.withGroupMutation(ctx, a, ref, func(st *permissionGroupStore, g groupTarget) error {
		if !s.validRoleForPersona(s.groupSchemaOrDefault(), g.Persona, role) {
			return fmt.Errorf("role %q is not assignable in a %q group: %w", role, g.Persona, iam.ErrRoleNotAssignable)
		}
		if err := s.requireDefinedGroupRole(ctx, st, g.ID, g.Persona, role); err != nil {
			return err
		}
		q := db.New(st.q)
		id, bound, err := lockEnsureUser(ctx, st.q, key, value)
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
		current, err := st.directRole(ctx, g.ID, subject)
		if err != nil {
			return err
		}
		held, err := s.roleHeld(ctx, st, g, current, role)
		if err != nil {
			return err
		}
		if !held {
			if !created && !bound {
				return errmodel.E(errmodel.CodeContactNotVerified, errmodel.WithMetadata(map[string]any{
					"identifier": value, "channel": string(key), "reason": "contact_unproven",
				}))
			}
			if current != "" {
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
		outID = id
		return nil
	})
	if err != nil {
		return iam.User{}, err
	}
	return s.User(ctx, iam.UserByID(outID), iam.IncludeDeleted())
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
func lockEnsureUser(ctx context.Context, q db.DBTX, key iam.UserKey, value string) (id string, bound bool, err error) {
	var sql string
	switch key {
	case iam.UserKeyID:
		sql = `SELECT id::text, true, deleted_at IS NOT NULL FROM users WHERE id=$1::uuid FOR UPDATE`
	case iam.UserKeyEmail:
		sql = `SELECT id::text, email_verified, deleted_at IS NOT NULL FROM users WHERE email=$1::text::public.citext FOR UPDATE`
	default:
		sql = `SELECT id::text, phone_verified, deleted_at IS NOT NULL FROM users WHERE phone_number=$1 FOR UPDATE`
	}
	var deleted bool
	err = q.QueryRow(ctx, sql, value).Scan(&id, &bound, &deleted)
	switch {
	case errors.Is(err, pgx.ErrNoRows):
		return "", false, nil
	case err != nil:
		return "", false, err
	case deleted:
		return "", false, fmt.Errorf("the account with %s %s is deleted: %w", key, value, iam.ErrUserNotFound)
	}
	return id, bound, nil
}

// roleHeld reports whether current already gives what role would: the same
// role, the group's owner role, or a role whose grants cover role's.
func (s *Engine) roleHeld(ctx context.Context, st *permissionGroupStore, g groupTarget, current, role iam.Role) (bool, error) {
	switch current {
	case "":
		return false, nil
	case role, iam.OwnerRole:
		return true, nil
	}
	have, err := s.roleGrants(ctx, st, g, current)
	if errors.Is(err, iam.ErrRoleNotAssignable) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	want, err := s.roleGrants(ctx, st, g, role)
	if err != nil {
		return false, err
	}
	return grantsCoverAll(have, want), nil
}
