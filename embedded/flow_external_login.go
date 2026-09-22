package embedded

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
	// Link authorizes a provider mutation only; it never creates a session.
	Link               *ExternalLinkAuthorization
	AccountInviteToken string
	Event              string // session-created audit event, e.g. "oidc_login"
	UserAgent          string
	IP                 string
}

// ExternalLinkAuthorization records the fresh session that initiated linking.
// It is carried only in server-side browser state, never accepted from a callback.
type ExternalLinkAuthorization struct {
	UserID          string
	SessionID       string
	AuthenticatedAt time.Time
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
// ErrUserCreationFailed. Session and MFA errors come from the shared login workflow.
func (s *Runtime) CompleteExternalLogin(ctx context.Context, in ExternalLoginInput) (LoginOutcome, error) {
	userID, created, err := s.ResolveExternalIdentity(ctx, in)
	if err != nil {
		return LoginOutcome{}, err
	}
	if in.Link != nil {
		return LoginOutcome{Kind: LoginProviderLinked, UserID: userID}, nil
	}
	var version int64
	var providerID string
	err = s.pg.QueryRow(ctx, `SELECT u.credential_version,p.id::text FROM users u JOIN user_providers p ON p.user_id=u.id WHERE u.id=$1::uuid AND p.issuer=$2 AND p.subject=$3 AND p.verified_at IS NOT NULL`, userID, in.Identity.Issuer, in.Identity.Subject).Scan(&version, &providerID)
	if err != nil {
		return LoginOutcome{}, err
	}
	out, err := s.finishFirstFactor(ctx, loginProof{ProviderID: providerID, ProviderIssuer: in.Identity.Issuer, ProviderSubject: in.Identity.Subject, Version: version, AuthenticatedAt: time.Now().UTC(), Input: LoginSessionInput{UserID: userID, AuthMethods: []string{"oauth"}, Event: in.Event, Extra: map[string]any{"provider": in.Identity.Provider}, UserAgent: in.UserAgent, IP: in.IP}})
	out.Created = created
	if err == nil && created {
		s.SendWelcome(ctx, userID)
	}
	return out, err
}

// ResolveExternalIdentity maps a verified provider identity to a local user
// without issuing a session: the explicit link target, the already-linked
// account, or a newly registered one (created reports the last case).
func (s *Runtime) ResolveExternalIdentity(ctx context.Context, in ExternalLoginInput) (userID string, created bool, err error) {
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
			return "", false, ErrAccountExistsLinkRequired
		}
	}
	if s.cfg.Registration.NativeUserMode == RegistrationModeClosed {
		return "", false, ErrRegistrationDisabled
	}
	username := s.DeriveUsernameForOAuth(ctx, provider, id.PreferredUsername, accountEmail, id.DisplayName)
	u, err := s.registerAccount(ctx, accountRegistration{User: ImportUserInput{Email: accountEmail, Username: username, EmailVerified: accountEmail != ""}, Provider: &id, InviteToken: in.AccountInviteToken})
	if err != nil {
		return "", false, err
	}
	return u.ID, true, nil
}
