package embedded

// External-identity login as ONE engine decision (ak#318): mapping a verified
// provider identity (OIDC / OAuth2) to a local account — the explicit link
// target, the already-linked account, or a fresh registration — and issuing
// the session. The C-2 rule lives here: a fresh identity is never linked to
// an existing account by its asserted email.

import (
	"context"
	"errors"
	"fmt"
	stdlog "log"
	"strings"

	authkit "github.com/open-rails/authkit"
)

// ExternalIdentity is a provider-verified identity.
type ExternalIdentity struct {
	Provider          string // provider slug (the configured name)
	Issuer            string
	Subject           string
	Email             string
	EmailVerified     bool
	PreferredUsername string
	DisplayName       string
}

// ExternalLoginInput is an external-identity login or link attempt.
type ExternalLoginInput struct {
	Identity ExternalIdentity
	// LinkUserID, when set, is the authenticated user explicitly linking this
	// identity (never a registration path).
	LinkUserID         string
	AccountInviteToken string
	Event              string // session-created audit event, e.g. "oidc_login"
	UserAgent          string
	IP                 string
}

// ExternalLoginOutcomeKind is the closed set of ways an external login ends.
type ExternalLoginOutcomeKind string

const (
	ExternalSessionIssued           ExternalLoginOutcomeKind = "session_issued"
	ExternalTwoFAEnrollmentRequired ExternalLoginOutcomeKind = "2fa_enrollment_required"
)

// ExternalLoginOutcome reports the resolved user, whether it was just created,
// and the session (for ExternalSessionIssued).
type ExternalLoginOutcome struct {
	Kind    ExternalLoginOutcomeKind
	UserID  string
	Created bool
	Session *IssuedSession
}

var (
	ErrAccountExistsLinkRequired    = authkit.ErrAccountExistsLinkRequired
	ErrProviderLinkFailed           = authkit.ErrProviderLinkFailed
	ErrUserCreationFailed           = authkit.ErrUserCreationFailed
	ErrProviderAlreadyLinked        = authkit.ErrProviderAlreadyLinked
	ErrProviderChangeRequiresUnlink = authkit.ErrProviderChangeRequiresUnlink
)

// CompleteExternalLogin resolves the identity to a user and signs it in.
// Resolution errors: ErrProviderAlreadyLinked, ErrProviderChangeRequiresUnlink,
// ErrAccountExistsLinkRequired, ErrRegistrationDisabled, ErrProviderLinkFailed,
// ErrUserCreationFailed. Session errors: ErrUserBanned, or a FlowError wrapping
// ErrSessionIssueFailed.
func (s *Client) CompleteExternalLogin(ctx context.Context, in ExternalLoginInput) (ExternalLoginOutcome, error) {
	userID, created, err := s.ResolveExternalIdentity(ctx, in)
	if err != nil {
		return ExternalLoginOutcome{}, err
	}
	session, err := s.IssueLoginSession(ctx, LoginSessionInput{
		UserID: userID, AuthMethods: []string{"oauth"}, Event: in.Event,
		Extra: map[string]any{"provider": in.Identity.Provider}, UserAgent: in.UserAgent, IP: in.IP,
	})
	if err != nil {
		if errors.Is(err, ErrTwoFAEnrollmentRequired) {
			return ExternalLoginOutcome{Kind: ExternalTwoFAEnrollmentRequired, UserID: userID, Created: created}, nil
		}
		if errors.Is(err, ErrUserBanned) {
			return ExternalLoginOutcome{}, err
		}
		return ExternalLoginOutcome{}, stageErr("issue_session", fmt.Errorf("%w: %w", ErrSessionIssueFailed, err))
	}
	if created {
		s.SendWelcome(ctx, userID)
	}
	return ExternalLoginOutcome{Kind: ExternalSessionIssued, UserID: userID, Created: created, Session: &session}, nil
}

// ResolveExternalIdentity maps a verified provider identity to a local user
// without issuing a session: the explicit link target, the already-linked
// account, or a newly registered one (created reports the last case).
func (s *Client) ResolveExternalIdentity(ctx context.Context, in ExternalLoginInput) (userID string, created bool, err error) {
	id := in.Identity
	issuer, provider := id.Issuer, id.Provider
	var emailPtr *string
	if e := strings.TrimSpace(id.Email); e != "" {
		emailPtr = &e
	}
	setUsername := func(userID, note string) {
		if strings.TrimSpace(id.PreferredUsername) == "" {
			return
		}
		if err := s.SetProviderUsername(ctx, userID, issuer, id.Subject, id.PreferredUsername); err != nil {
			stdlog.Printf("[authkit/security] warning: SetProviderUsername failed (user=%s issuer=%s); %s: %v", userID, issuer, note, err)
		}
	}

	if in.LinkUserID != "" {
		if uid0, _, err := s.GetProviderLinkByIssuer(ctx, issuer, id.Subject); err == nil && uid0 != "" && uid0 != in.LinkUserID {
			return "", false, ErrProviderAlreadyLinked
		}
		// The provider link is the load-bearing write: a failure must NOT report
		// success, or the next login won't find the link and diverges.
		if err := s.LinkProviderByIssuer(ctx, in.LinkUserID, issuer, provider, id.Subject, emailPtr); err != nil {
			if errors.Is(err, ErrProviderAlreadyLinked) || errors.Is(err, ErrProviderChangeRequiresUnlink) {
				return "", false, err
			}
			stdlog.Printf("[authkit/security] error: provider link write failed (user=%s issuer=%s); failing external login: %v", in.LinkUserID, issuer, err)
			return "", false, fmt.Errorf("%w: %w", ErrProviderLinkFailed, err)
		}
		setUsername(in.LinkUserID, "link succeeded, username not updated")
		return in.LinkUserID, false, nil
	}
	if uid, _, err := s.GetProviderLinkByIssuer(ctx, issuer, id.Subject); err == nil && uid != "" {
		setUsername(uid, "login succeeded, username not updated")
		return uid, false, nil
	}

	// Trust the IdP's email only when it is explicitly verified (ak#284).
	accountEmail := ""
	if id.EmailVerified {
		accountEmail = strings.TrimSpace(id.Email)
	}
	// C-2: never silently link a fresh provider identity to a pre-existing
	// local account by matching its asserted email — the user must sign in and
	// link the provider explicitly.
	if accountEmail != "" {
		if u, err := s.GetUserByEmail(ctx, accountEmail); err == nil && u != nil {
			return "", false, ErrAccountExistsLinkRequired
		}
	}
	// Auto-creating an account is a public registration path. InviteOnly
	// requires an unbound account invite token carried from flow start.
	if s.cfg.Registration.NativeUserMode == RegistrationModeInviteOnly {
		allowed, err := s.RegistrationAllowedForEmailWithInvite(ctx, accountEmail, in.AccountInviteToken)
		if err != nil {
			return "", false, err
		}
		if !allowed {
			return "", false, ErrRegistrationDisabled
		}
	} else if !s.PublicNativeUserRegistrationEnabled() {
		return "", false, ErrRegistrationDisabled
	}
	username := s.DeriveUsernameForOAuth(ctx, provider, id.PreferredUsername, accountEmail, id.DisplayName)
	u, err := s.CreateUser(ctx, accountEmail, username)
	if err != nil || u == nil {
		return "", false, ErrUserCreationFailed
	}
	// Without a create+link transaction a failure here leaves an orphan user
	// row; logged CRITICAL for cleanup rather than reported as success.
	if err := s.LinkProviderByIssuer(ctx, u.ID, issuer, provider, id.Subject, emailPtr); err != nil {
		stdlog.Printf("[authkit/security] CRITICAL: provider link write failed after user creation (orphan user=%s issuer=%s subject=%s); failing external login — manual cleanup may be required: %v", u.ID, issuer, id.Subject, err)
		return "", false, fmt.Errorf("%w: %w", ErrProviderLinkFailed, err)
	}
	if accountEmail != "" {
		if err := s.MarkEmailVerified(ctx, u.ID); err != nil {
			stdlog.Printf("[authkit/security] warning: MarkEmailVerified failed for new user %s (recoverable; user+link created): %v", u.ID, err)
		}
	}
	if err := s.ConsumeAccountRegistrationInvite(ctx, accountEmail, u.ID, in.AccountInviteToken); err != nil {
		return "", false, err
	}
	setUsername(u.ID, "cosmetic")
	return u.ID, true, nil
}
