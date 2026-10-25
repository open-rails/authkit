package auth

import (
	"context"
	"errors"
	"net/http"
	"time"
)

// Authenticator is the host's auth as a library takes it to guard its own
// routes. It only says who a request is; the library builds its gates from
// the Verified it returns, so the host writes no middleware.
type Authenticator interface {
	// Authenticate verifies r's credential (its Authorization header or
	// cookie, and any sender proof) and returns its Verified, or nil and an
	// error. It checks live: a credential whose sign-in was revoked, or whose
	// account is banned or deleted, is refused, not admitted until a token
	// expires. It admits people and applications alike.
	//
	// Its error matches ErrUnauthenticated when r carries no valid
	// credential, joined with ErrExpired, ErrRevoked or
	// ErrSenderProofRequired when that is why; ErrForbidden for a valid
	// credential the provider refuses here; ErrUnavailable when it could not
	// verify. It may be a *Challenge carrying the provider's headers.
	//
	// It is safe for concurrent use. A consumer calls it at most once per
	// request (a sender proof is spent once) and keeps the Verified for that
	// request alone; a provider whose own middleware already verified r's
	// credential reuses that verification.
	Authenticate(r *http.Request) (Verified, error)
}

// Verified is one request's verified credential. A consumer keeps it only
// for that request: never for another request, nor after the credential,
// method or signed URL changes. It may implement CredentialChecker, PermissionChecker, DirectPermissionChecker,
// RecentSignInChecker, Bound and Asserted; an identity-only provider
// implements none.
type Verified interface {
	Identity() Identity
}

// CredentialChecker is an optional capability for consumers that retain one
// verified user credential while waiting inside its original request. It checks
// that credential's original effective expiry and live account/session or
// application/client/group registration, without authenticating again, consuming
// another sender proof, granting permissions or requiring a recent sign-in.
//
// Unsupported credentials must fail closed with ErrForbidden. AuthKit initially
// supports native user and resource-user credentials; the presence of this method
// does not imply support for API keys, PATs or client-credentials tokens. A wrapper
// that exposes this capability must forward it to its original Verified.
//
// ErrExpired or ErrRevoked joined with ErrUnauthenticated means the credential
// ended. ErrUnavailable means its live authority could not be checked. A
// successful check grants no permissions; consumers still apply resource policy.
type CredentialChecker interface {
	CheckCredential(ctx context.Context) error
}

// Scope names an authority-owned immutable resource, such as the group
// whose members administer a merchant: Authority is the issuer whose groups
// it is in, ID its id there. The consumer keeps it beside the resource, or
// asks the Authenticator's RootScope (Root); names and request selectors
// grant nothing.
type Scope struct {
	Authority string
	ID        string
}

// PermissionChecker is an optional capability of a Verified request. Can
// reports whether the request holds exactly permission (never a pattern) in
// exactly scope, checked live and without verifying the request again: a
// scope of another authority, or outside the scope the credential is bound
// to (Bound, with its one exception), is false, and the credential's
// ceilings hold. Consumers deny privileged
// access without this capability; identity metadata never implies a grant.
// An error never grants: one matching ErrExpired or ErrRevoked (with
// ErrUnauthenticated) means the credential ended after the request was
// verified (401); any other means the check could not run (503).
type PermissionChecker interface {
	Can(ctx context.Context, scope Scope, permission string) (bool, error)
}

// DirectPermissionChecker checks grants held directly in the requested scope.
// It has the same live credential, session, ceiling and scope-binding checks
// as PermissionChecker, but does not inherit grants from a wider root scope.
// Consumers use it when tenants or apps must have explicit local authority.
// The absence of this capability must fail closed, never fall back to Can.
type DirectPermissionChecker interface {
	CanDirect(ctx context.Context, scope Scope, permission string) (bool, error)
}

// RecentSignInChecker is an optional capability of a person's Verified
// request, for actions that move money or grant access. CheckRecentSignIn is
// nil when the credential's own sign-in is recent enough by the provider's
// policy, checked without verifying the request again. Otherwise its error
// matches ErrStepUpRequired when the person must sign in again (a *Challenge
// gives the policy's MaxAge and the provider's Metadata); ErrExpired or
// ErrRevoked (with ErrUnauthenticated) when the credential ended;
// ErrForbidden for a credential with no sign-in of its own (an
// application's, an API key); ErrUnavailable when the check could not run.
// Consumers refuse those actions to a person whose request lacks it.
type RecentSignInChecker interface {
	CheckRecentSignIn(ctx context.Context) error
}

// PermissionCatalog is an optional capability of an Authenticator: the
// permissions it knows. A consumer checks the permissions it is configured
// with when it mounts its routes, so a misspelled one fails then instead of
// refusing every request.
type PermissionCatalog interface {
	KnownPermission(permission string) bool
}

// Bound is an optional capability of a Verified request. BoundScope is the
// one scope the credential acts in, such as a group's API key or service
// token, a trusted issuer's token for its group, or a person's token
// exchanged for one group, and the zero Scope when it is bound to none, as a
// person's own sign-in is. A bound credential's Can is false outside it, with
// one exception: a person's (SubjectUser) may also hold, in the
// Authenticator's RootScope (Root), the root: permissions the person holds
// there, since a person keeps their root role whatever group a token names.
// An application's is false everywhere else. A consumer serving one scope's
// resources admits there only a credential bound to that scope; without
// this capability a credential is bound to none.
type Bound interface {
	BoundScope() Scope
}

// Asserted is an optional capability of a Verified request. Asserted is
// true for a credential minted from an application's assertion naming one of
// the application's own users (the RFC 7523 JWT bearer grant), such as a
// merchant backend's token for its customer, and false for any other: a
// session, an API key, a token exchanged for a resource, a trusted issuer's
// own token. Without this capability a credential is not asserted.
type Asserted interface {
	Asserted() bool
}

// Root is an optional capability of an Authenticator. RootScope is the scope
// its root permissions (root:<resource>:<action>) are held in, which spans
// everything the deployment serves, such as AuthKit's root group. A consumer
// checks a root: permission there (PermissionChecker.Can), so its host
// configures no scope; without Root a consumer grants no root: permission.
// Its error matches ErrUnavailable when the scope could not be resolved.
type Root interface {
	RootScope(ctx context.Context) (Scope, error)
}

// Headers is an optional capability of an Authenticator: the header names
// its credentials use across origins. A consumer merges them into its CORS
// lists, so it never names a provider's headers itself.
type Headers interface {
	// AllowedHeaders are the request headers a client sends credentials in
	// (Access-Control-Allow-Headers), such as Authorization and DPoP.
	AllowedHeaders() []string
	// ExposedHeaders are the response headers a client reads
	// (Access-Control-Expose-Headers), such as WWW-Authenticate and
	// DPoP-Nonce: every header a Challenge of the provider carries.
	ExposedHeaders() []string
}

// Failures are classified with errors.Is. Providers wrap their own errors in
// them; consumers never show provider error text to clients.
var (
	// ErrUnauthenticated: no valid credential (401).
	ErrUnauthenticated = errors.New("authentication required")
	// ErrForbidden: a valid credential the policy refuses (403).
	ErrForbidden = errors.New("authentication policy refused")
	// ErrUnavailable: the check could not run (503).
	ErrUnavailable = errors.New("authentication unavailable")
	// ErrSenderProofRequired: a sender-constrained token without its valid
	// proof (401).
	ErrSenderProofRequired = errors.New("sender proof required")
	// ErrExpired: the credential expired (401).
	ErrExpired = errors.New("credential expired")
	// ErrRevoked: the credential or its sign-in was revoked, or its account
	// banned or deleted (401).
	ErrRevoked = errors.New("credential revoked")
	// ErrStepUpRequired: the person must sign in again (401, RFC 9470).
	ErrStepUpRequired = errors.New("step-up required")
)

// Challenge is a provider's error with detail for the refusal. errors.Is
// and errors.As see through it to Err, which classifies it; Refuse reads the
// rest.
type Challenge struct {
	Err error
	// MaxAge is, with ErrStepUpRequired, how recent a sign-in the action
	// needs (RFC 9470 max_age); zero says nothing.
	MaxAge time.Duration
	// Header is set on the refusal, replacing Refuse's own values: a DPoP
	// challenge's WWW-Authenticate and DPoP-Nonce.
	Header http.Header
	// Metadata is the provider's challenge for its own client, such as its
	// step-up methods. Consumers return it unchanged and never read it.
	Metadata map[string]any
}

func (c *Challenge) Error() string {
	if c.Err == nil {
		return "authentication challenge"
	}
	return c.Err.Error()
}

func (c *Challenge) Unwrap() error { return c.Err }
