package engine

import (
	"context"
	"errors"

	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/internal/errmodel"
)

// registrationAdmitted is the one public self-registration policy check:
// open admits every sign-up, invite_only one whose context carries a live
// invitation's code (an invite link or an email invitation: the code is the
// credential, never the address), closed none.
func (s *Engine) registrationAdmitted(ctx context.Context) (bool, error) {
	switch s.cfg.Registration {
	case iam.RegistrationModeOpen:
		return true, nil
	case iam.RegistrationModeInviteOnly:
		invite, err := s.presentedInvite(ctx, accountRegistrationInviteTokenFromContext(ctx))
		if refusedInvitation(err) {
			return false, nil
		}
		return invite != nil, err
	default: // Closed, and any unrecognized value: fail closed.
		return false, nil
	}
}

// refusedInvitation reports whether err refuses a presented invitation.
func refusedInvitation(err error) bool {
	return errors.Is(err, iam.ErrInvitationNotFound) || errors.Is(err, errmodel.ErrInvitationRevoked) ||
		errors.Is(err, errmodel.ErrInvitationExpired) || errors.Is(err, iam.ErrInvitationsDisabled)
}
