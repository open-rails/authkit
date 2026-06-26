package authcore

import "context"

// registrationAllowedForEmail is the SINGLE email-aware chokepoint for public
// self-registration policy (#147). Public-registration gates that have the
// registrant's email route through it instead of threading invite-awareness
// through ~10 divergent call sites (PublicNativeUserRegistrationEnabled() takes no
// email, which is exactly why this email-aware helper exists):
//
//	Open       — always true.
//	Closed      — always false.
//	InviteOnly — true iff a valid, unconsumed, unexpired account-registration invite
//	             CODE is presented on ctx (#147 FINAL: the stranger invite is UNBOUND;
//	             the single-use code is the credential, not the email).
func (s *Service) registrationAllowedForEmail(ctx context.Context, email string) (bool, error) {
	mode, err := normalizeRegistrationMode(s.opts.NativeUserRegistrationMode)
	if err != nil {
		return false, nil
	}
	switch mode {
	case RegistrationModeOpen:
		return true, nil
	case RegistrationModeInviteOnly:
		return s.hasValidAccountRegistrationInvite(ctx, email)
	default: // Closed, and any unrecognized value: fail closed.
		return false, nil
	}
}

// hasValidAccountRegistrationInvite is implemented in
// account_registration_invites.go. It requires a valid single-use account-invite
// code on ctx (UNBOUND — no email match); group invite tokens are a separate code.
