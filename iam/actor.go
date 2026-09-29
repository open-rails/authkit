package iam

import "strings"

// ActorKind is the class of authority an Actor carries.
type ActorKind string

const (
	ActorUser              ActorKind = "user"
	ActorAPIKey            ActorKind = "api_key"
	ActorRemoteApplication ActorKind = "remote_application"
	ActorDelegated         ActorKind = "delegated"
	ActorOperator          ActorKind = "operator"
)

// Actor is who performs an operation. Its fields are unexported: the zero
// Actor is invalid and every operation refuses it, and OperatorActor is the
// only way to build an operator. Authority is resolved live per operation;
// nothing is cached in the value.
type Actor struct {
	kind  ActorKind
	id    string
	grant *DelegatedGrant
	// ceilings narrow authority; each one must cover a permission. nil = unbounded.
	ceilings [][]Perm
}

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

// OperatorActor is the trusted host authority. It skips authority rules but
// never invariants (last owner, MFA-required roles). Never derive it from
// request input.
func OperatorActor() Actor { return Actor{kind: ActorOperator} }

func newActor(kind ActorKind, id string) Actor {
	id = strings.TrimSpace(id)
	if id == "" {
		return Actor{}
	}
	return Actor{kind: kind, id: id}
}

// Within narrows the actor to permissions covered by perms (an intersection
// with any existing ceiling). On an operator or the zero Actor it returns the
// zero Actor.
func (a Actor) Within(perms ...Perm) Actor {
	if a.kind == "" || a.kind == ActorOperator {
		return Actor{}
	}
	ceilings := make([][]Perm, len(a.ceilings), len(a.ceilings)+1)
	copy(ceilings, a.ceilings)
	a.ceilings = append(ceilings, append([]Perm{}, perms...))
	return a
}

func (a Actor) Kind() ActorKind { return a.kind }

// ID is the user, API key, application or delegated subject id; "" for an operator.
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
		if !AnyGrantCovers(permStrings(c), perm) {
			return false
		}
	}
	return true
}

// String is "<kind>:<id>" (or "operator"), for logs and audit.
func (a Actor) String() string {
	switch a.kind {
	case "":
		return "invalid"
	case ActorOperator:
		return string(ActorOperator)
	}
	return string(a.kind) + ":" + a.id
}

func permStrings(perms []Perm) []string {
	out := make([]string, len(perms))
	for i, p := range perms {
		out[i] = string(p)
	}
	return out
}
