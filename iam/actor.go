package iam

import (
	"slices"
	"strings"
)

// ActorKind is the class of authority an Actor carries.
type ActorKind string

const (
	ActorUser              ActorKind = "user"
	ActorAPIKey            ActorKind = "api_key"
	ActorRemoteApplication ActorKind = "remote_application"
	ActorDelegated         ActorKind = "delegated"
	ActorSystem            ActorKind = "system"
)

// Actor is who performs an operation. Its fields are unexported: the zero
// Actor is invalid and every operation refuses it, and SystemActor is the
// only way to build the system actor. Authority is resolved live per operation;
// nothing is cached in the value.
type Actor struct {
	kind    ActorKind
	id      string
	grant   *DelegatedGrant
	session SessionRef
	// ceilings narrow authority; each one must cover a permission. nil = unbounded.
	ceilings [][]Perm
}

// SessionRef names the sign-in an access token was minted from: a refresh
// session (claim sid) or a device key (claim device_key_id), never both.
type SessionRef struct {
	SessionID   string
	DeviceKeyID string
}

// IsZero reports whether r names no sign-in.
func (r SessionRef) IsZero() bool { return r.SessionID == "" && r.DeviceKeyID == "" }

// DelegatedGrant is copied from a verified delegated access token.
type DelegatedGrant struct {
	Issuer  string
	Subject string // delegated_sub
	// Permissions are always a ceiling.
	Permissions []Perm
	// RemoteApplicationID is set when the token is bound to an application.
	RemoteApplicationID string
	// GroupID is that application's controlling group.
	GroupID string
}

// UserActor acts as a native user.
func UserActor(userID string) Actor { return newActor(ActorUser, userID) }

// APIKeyActor acts as an API key: APIKey.ID, the same value as verify Claims.APIKeyID.
func APIKeyActor(apiKeyID string) Actor { return newActor(ActorAPIKey, apiKeyID) }

// RemoteApplicationActor acts as a registered remote application.
func RemoteApplicationActor(appID string) Actor {
	return newActor(ActorRemoteApplication, appID)
}

// DelegatedActor acts under a verified delegated grant. A grant from a foreign
// platform carries no AuthKit authority.
func DelegatedActor(g DelegatedGrant) Actor {
	g.Issuer, g.Subject = strings.TrimSpace(g.Issuer), strings.TrimSpace(g.Subject)
	if g.Issuer == "" || g.Subject == "" {
		return Actor{}
	}
	g.Permissions = append([]Perm(nil), g.Permissions...)
	a := Actor{kind: ActorDelegated, id: g.Subject, grant: &g}
	return a.Within(g.Permissions...)
}

// SystemActor is your application's own code acting, with no user: trusted
// host authority. It skips authority rules but never invariants (last owner,
// MFA-required roles). Never derive it from request input.
func SystemActor() Actor { return Actor{kind: ActorSystem} }

func newActor(kind ActorKind, id string) Actor {
	id = strings.TrimSpace(id)
	if id == "" {
		return Actor{}
	}
	return Actor{kind: kind, id: id}
}

// InSession binds a user or delegated actor to the sign-in its token was
// minted from. Every authority check then also requires that session or
// device key to be active, in the same query as the account check, and
// refuses a revoked one with ErrSessionRevoked. verify.ActorFromClaims binds
// every actor it builds from an AuthKit user or delegated token; an unbound
// actor (UserActor in trusted server code) is checked at account level only.
// The zero ref leaves a unchanged; any other actor, or a ref naming both, is
// the zero Actor.
func (a Actor) InSession(r SessionRef) Actor {
	r.SessionID, r.DeviceKeyID = strings.TrimSpace(r.SessionID), strings.TrimSpace(r.DeviceKeyID)
	switch {
	case r.IsZero():
		return a
	case a.kind != ActorUser && a.kind != ActorDelegated, r.SessionID != "" && r.DeviceKeyID != "":
		return Actor{}
	}
	a.session = r
	return a
}

// Session is the sign-in a is bound to (InSession).
func (a Actor) Session() (SessionRef, bool) { return a.session, !a.session.IsZero() }

// Within narrows the actor to permissions covered by perms (an intersection
// with any existing ceiling). On the system or the zero Actor it returns the
// zero Actor.
func (a Actor) Within(perms ...Perm) Actor {
	if a.kind == "" || a.kind == ActorSystem {
		return Actor{}
	}
	ceilings := make([][]Perm, len(a.ceilings), len(a.ceilings)+1)
	copy(ceilings, a.ceilings)
	a.ceilings = append(ceilings, append([]Perm{}, perms...))
	return a
}

func (a Actor) Kind() ActorKind { return a.kind }

// ID is the user, API key, application or delegated subject id; "" for the system.
func (a Actor) ID() string { return a.id }

// IsZero reports whether a is the invalid zero Actor.
func (a Actor) IsZero() bool { return a.kind == "" }

// Delegation returns the delegated grant of a delegated actor.
func (a Actor) Delegation() (DelegatedGrant, bool) {
	if a.grant == nil {
		return DelegatedGrant{}, false
	}
	g := *a.grant
	g.Permissions = append([]Perm(nil), g.Permissions...)
	return g, true
}

// Bounded reports whether a ceiling narrows the actor.
func (a Actor) Bounded() bool { return a.ceilings != nil }

// CeilingCovers reports whether every ceiling permits perm (true when unbounded).
func (a Actor) CeilingCovers(perm Perm) bool {
	for _, c := range a.ceilings {
		if !slices.ContainsFunc(c, perm.Matches) {
			return false
		}
	}
	return true
}

// String is "<kind>:<id>" (or "system"), for logs and audit.
func (a Actor) String() string {
	switch a.kind {
	case "":
		return "invalid"
	case ActorSystem:
		return string(ActorSystem)
	}
	return string(a.kind) + ":" + a.id
}
