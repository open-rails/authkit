// Package auth is the contract between a host's auth (the provider) and a
// library that guards its own routes with it (the consumer): the provider
// says who a request is (Authenticator), and the consumer decides what to
// admit from the Verified request, its optional permission and recent
// sign-in checks, and answers refusals the same way as every other consumer
// (Refuse). It contains no verifier or authorization policy.
package auth

// SubjectKind is what kind of native account a subject is.
type SubjectKind string

const (
	// SubjectUser is a person's account.
	SubjectUser SubjectKind = "user"
	// SubjectApplication is an application's account: a registered
	// application or service.
	SubjectApplication SubjectKind = "application"
)

// CredentialKind is how a request proved which subject it acts as.
type CredentialKind string

const (
	// CredentialSession is a token of a user's interactive sign-in.
	CredentialSession CredentialKind = "session"
	// CredentialDeviceKey is a token of a device key's sign-in.
	CredentialDeviceKey CredentialKind = "device_key"
	// CredentialAPIKey is an API key.
	CredentialAPIKey CredentialKind = "api_key"
	// CredentialSignedToken is a token an application signed with its own
	// registered keys.
	CredentialSignedToken CredentialKind = "signed_token"
	// CredentialAccessToken is a token the issuer or an authorization server
	// minted, with no sign-in of its own.
	CredentialAccessToken CredentialKind = "access_token"
)

// Credential is the mechanism that proved a request, never the subject: a
// subject's keys and tokens come and go while the subject stays.
type Credential struct {
	Kind CredentialKind
	// ID names the credential when it has one: the session, device key or
	// API key, or a token's jti.
	ID string
	// state is the provider's own record of what the credential may do (its
	// session, ceiling, scope). Only the provider can read it as authority,
	// and encoding drops it, so an Identity built or decoded from data grants
	// nothing.
	state any
}

// State is the provider's record of the credential's bounds; nil for a
// Credential the provider did not produce.
func (c Credential) State() any { return c.state }

// WithState is c carrying a provider's record of its bounds. The provider
// accepts only a state of its own type, which nobody else can construct, and
// it must be comparable (a pointer), as Identity is.
func (c Credential) WithState(state any) Credential {
	c.state = state
	return c
}

// Invoker is who actually acts, in its own issuer's namespace. It is the
// subject itself ({Issuer, Subject}) unless someone acts on the subject's
// behalf, such as an application's user spending the application's
// authority, who may be foreign.
type Invoker struct {
	Issuer string
	ID     string
}

// Identity is the authenticated request. Subject is the account native to
// Issuer whose authority and money the request uses: a user or an
// application. Invoker is who actually acts: always set, equal to the
// subject unless someone acts on its behalf. Credential is how the request
// was proven. Authorization is the subject's, narrowed by the credential;
// limits and budgets are per invoker within the subject; audit records all
// three. Contact fields are optional metadata, not authority.
type Identity struct {
	Issuer        string
	Subject       string
	SubjectKind   SubjectKind
	Invoker       Invoker
	Credential    Credential
	Email         string
	Username      string
	EmailVerified bool
}

// SelfInvoked reports whether the subject acts for itself.
func (i Identity) SelfInvoked() bool {
	return i.Invoker == Invoker{Issuer: i.Issuer, ID: i.Subject}
}
