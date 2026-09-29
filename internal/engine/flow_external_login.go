package engine

// External-identity login as ONE engine decision (ak#318): mapping a verified
// provider identity (OIDC / OAuth2) to a local account — the explicit link
// target, the already-linked account, or a fresh registration — and issuing
// the session. The C-2 rule lives here: a fresh identity is never linked to
// an existing account by its asserted email.

import (
	"context"
	stdlog "log"
	"strings"
	"time"

	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/internal/authflow"
	"github.com/open-rails/authkit/internal/errmodel"
)

// CompleteExternalLogin resolves the identity to a user and signs it in.
// Resolution errors: ErrProviderAlreadyLinked, ErrProviderChangeRequiresUnlink,
// ErrAccountExistsLinkRequired, ErrRegistrationDisabled, ErrProviderLinkFailed,
// ErrUserCreationFailed. Session and MFA errors come from the shared login workflow.
func (s *Engine) CompleteExternalLogin(ctx context.Context, in authflow.ExternalLoginInput) (authflow.LoginOutcome, error) {
	userID, created, err := s.resolveExternalIdentity(ctx, in)
	if err != nil {
		return authflow.LoginOutcome{}, err
	}
	if in.Link != nil {
		return authflow.LoginOutcome{Kind: authflow.LoginProviderLinked, UserID: userID}, nil
	}
	var version int64
	var providerID string
	err = s.pg.QueryRow(ctx, `SELECT u.credential_version,p.id::text FROM users u JOIN user_providers p ON p.user_id=u.id WHERE u.id=$1::uuid AND p.issuer=$2 AND p.subject=$3 AND p.verified_at IS NOT NULL`, userID, in.Identity.Issuer, in.Identity.Subject).Scan(&version, &providerID)
	if err != nil {
		return authflow.LoginOutcome{}, err
	}
	out, err := s.finishFirstFactor(ctx, loginProof{ProviderID: providerID, ProviderIssuer: in.Identity.Issuer, ProviderSubject: in.Identity.Subject, Version: version, AuthenticatedAt: time.Now().UTC(), Input: loginSessionInput{UserID: userID, AuthMethods: []string{"oauth"}, Event: in.Event, Extra: map[string]any{"provider": in.Identity.Provider}, UserAgent: in.UserAgent, IP: in.IP}})
	out.Created = created
	if err == nil && created {
		s.SendWelcome(ctx, userID)
	}
	return out, err
}

// resolveExternalIdentity maps a verified provider identity to a local user
// without issuing a session: the explicit link target, the already-linked
// account, or a newly registered one (created reports the last case).
func (s *Engine) resolveExternalIdentity(ctx context.Context, in authflow.ExternalLoginInput) (userID string, created bool, err error) {
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
		if err := s.setProviderUsername(ctx, userID, issuer, id.Subject, id.PreferredUsername); err != nil {
			stdlog.Printf("[authkit/security] warning: SetProviderUsername failed (user=%s issuer=%s); %s: %v", userID, issuer, note, err)
		}
	}

	if in.Link != nil {
		if err := s.completeProviderLink(ctx, *in.Link, id, emailPtr); err != nil {
			return "", false, err
		}
		return in.Link.UserID, false, nil
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
			return "", false, errmodel.ErrAccountExistsLinkRequired
		}
	}
	if s.cfg.Registration.NativeUserMode == iam.RegistrationModeClosed {
		return "", false, errmodel.ErrRegistrationDisabled
	}
	username := s.deriveUsernameForOAuth(ctx, provider, id.PreferredUsername, accountEmail, id.DisplayName)
	u, err := s.registerAccount(ctx, accountRegistration{User: iam.ImportUserInput{Email: accountEmail, Username: username, EmailVerified: accountEmail != ""}, Provider: &id, InviteToken: in.AccountInviteToken})
	if err != nil {
		return "", false, err
	}
	return u.ID, true, nil
}
