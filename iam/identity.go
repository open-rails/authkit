package iam

import (
	"slices"
	"strings"

	"github.com/open-rails/helpers/auth"
)

// CredentialSystem is AuthKit's credential for the host's own code:
// SystemIdentity, and what UserIdentity and ApplicationIdentity assert.
const CredentialSystem auth.CredentialKind = "system"

// Every operation that depends on who acts takes an auth.Identity: its
// Subject, Invoker and Credential (docs/identity.md). AuthKit reads authority
// only from the credential's state (auth.Credential.State), a CredentialState
// that AuthKit alone builds: verify's gates for a verified request, and the
// constructors below for trusted server code. An Identity built or decoded
// from data carries none, and every operation refuses it, as it refuses the
// zero Identity. Editing an Identity's exported fields changes nothing it
// may do.

// SessionRef names the sign-in an access token was minted from: a refresh
// session (claim sid) or a device key (claim device_key_id), never both.
type SessionRef struct {
	SessionID   string
	DeviceKeyID string
}

// IsZero reports whether r names no sign-in.
func (r SessionRef) IsZero() bool { return r.SessionID == "" && r.DeviceKeyID == "" }

// CredentialState is AuthKit's record of what an Identity's credential may
// do: the account it acts as, the sign-in it stays bound to, the ceilings and
// the group that narrow it. Its fields are unexported, so nothing outside
// AuthKit builds one; the zero CredentialState grants nothing.
type CredentialState struct {
	system     bool
	subject    auth.SubjectKind
	credential auth.CredentialKind
	// id is the user's or application's id, or an API key's.
	id      string
	session SessionRef
	// ceilings narrow authority; each one must cover a permission. nil =
	// unbounded.
	ceilings [][]Perm
	// group pins authority to one group; "" = unpinned.
	group string
}

// StateOf is AuthKit's state of id's credential; false when it has none.
func StateOf(id auth.Identity) (CredentialState, bool) {
	s, ok := id.Credential.State().(*CredentialState)
	if !ok || s == nil || s.IsZero() {
		return CredentialState{}, false
	}
	return *s, true
}

func (s CredentialState) bind(id auth.Identity) auth.Identity {
	id.Credential = id.Credential.WithState(&s)
	return id
}

// SystemIdentity is your application's own code acting, with no user: trusted host
// authority. It skips authority rules but never invariants (last owner,
// MFA-required roles). Never derive it from request input.
func SystemIdentity() auth.Identity {
	return CredentialState{system: true, credential: CredentialSystem}.bind(auth.Identity{Credential: auth.Credential{Kind: CredentialSystem}})
}

// UserIdentity is your code acting as a native user, checked at account level: no
// sign-in binds it, unlike a verified user's token.
func UserIdentity(userID string) auth.Identity {
	return asserted(auth.SubjectUser, CredentialSystem, userID)
}

// APIKeyIdentity is your code acting as an API key (APIKey.ID, verify
// Claims.APIKeyID), with the key's live authority. Its Subject, the key's
// group, is resolved per operation.
func APIKeyIdentity(apiKeyID string) auth.Identity {
	return asserted(auth.SubjectApplication, auth.CredentialAPIKey, apiKeyID)
}

// ApplicationIdentity is your code acting as a registered remote application.
func ApplicationIdentity(appID string) auth.Identity {
	return asserted(auth.SubjectApplication, CredentialSystem, appID)
}

func asserted(subject auth.SubjectKind, credential auth.CredentialKind, id string) auth.Identity {
	id = strings.TrimSpace(id)
	if id == "" {
		return auth.Identity{}
	}
	out := auth.Identity{SubjectKind: subject, Credential: auth.Credential{Kind: credential}}
	if credential == auth.CredentialAPIKey {
		out.Credential.ID = id
	} else {
		out.Subject, out.Invoker = id, auth.Invoker{ID: id}
	}
	return CredentialState{subject: subject, credential: credential, id: id}.bind(out)
}

// InSession binds a user's identity to the sign-in its token was minted
// from. Every authority check then also requires that session or device key
// to be active, in the same query as the account check, and refuses a
// revoked one with ErrSessionRevoked. verify binds every identity it builds
// from an AuthKit user token; an unbound one
// (UserIdentity in trusted server code) is checked at account level only. The zero
// ref leaves id unchanged; any other identity, or a ref naming both, is the
// zero Identity.
func InSession(id auth.Identity, r SessionRef) auth.Identity {
	s, ok := StateOf(id)
	r.SessionID, r.DeviceKeyID = strings.TrimSpace(r.SessionID), strings.TrimSpace(r.DeviceKeyID)
	switch {
	case !ok:
		return auth.Identity{}
	case r.IsZero():
		return id
	case s.subject != auth.SubjectUser, r.SessionID != "" && r.DeviceKeyID != "":
		return auth.Identity{}
	}
	s.session = r
	return s.bind(id)
}

// Within narrows id to permissions covered by perms (an intersection with
// any existing ceiling). The system's or an identity without AuthKit's state
// is the zero Identity.
func Within(id auth.Identity, perms ...Perm) auth.Identity {
	s, ok := StateOf(id)
	if !ok || s.system {
		return auth.Identity{}
	}
	ceilings := make([][]Perm, len(s.ceilings), len(s.ceilings)+1)
	copy(ceilings, s.ceilings)
	s.ceilings = append(ceilings, append([]Perm{}, perms...))
	return s.bind(id)
}

// PinnedTo narrows id to the group groupID: an identity pinned to another
// group, the system's or one without AuthKit's state is the zero Identity.
func PinnedTo(id auth.Identity, groupID string) auth.Identity {
	s, ok := StateOf(id)
	groupID = strings.TrimSpace(groupID)
	switch {
	case !ok || s.system || groupID == "", s.group != "" && s.group != groupID:
		return auth.Identity{}
	}
	s.group = groupID
	return s.bind(id)
}

// IsZero reports whether s grants nothing: the zero CredentialState.
func (s CredentialState) IsZero() bool { return !s.system && s.id == "" }

// IsSystem reports whether s is SystemIdentity's: your own code, with host authority.
func (s CredentialState) IsSystem() bool { return s.system }

// SubjectKind is the kind of account s acts as; "" for the system.
func (s CredentialState) SubjectKind() auth.SubjectKind { return s.subject }

// ID is the user's or application's id, or the API key's; "" for the system.
func (s CredentialState) ID() string { return s.id }

// IsUser reports whether s acts as a user.
func (s CredentialState) IsUser() bool { return s.subject == auth.SubjectUser }

// IsAPIKey reports whether s is an API key's.
func (s CredentialState) IsAPIKey() bool { return s.credential == auth.CredentialAPIKey }

// IsApplication reports whether s acts as a registered application.
func (s CredentialState) IsApplication() bool {
	return s.subject == auth.SubjectApplication && s.credential != auth.CredentialAPIKey
}

// Session is the sign-in s is bound to (InSession).
func (s CredentialState) Session() (SessionRef, bool) { return s.session, !s.session.IsZero() }

// Group is the group s is pinned to (PinnedTo); "" when unpinned.
func (s CredentialState) Group() string { return s.group }

// Bounded reports whether a ceiling narrows s.
func (s CredentialState) Bounded() bool { return s.ceilings != nil }

// CeilingCovers reports whether every ceiling permits perm (true when
// unbounded).
func (s CredentialState) CeilingCovers(perm Perm) bool {
	for _, c := range s.ceilings {
		if !slices.ContainsFunc(c, perm.Matches) {
			return false
		}
	}
	return true
}

// String is "<subject kind>:<id>" ("api_key:<id>" for a key, "system"), for
// logs.
func (s CredentialState) String() string {
	switch {
	case s.system:
		return string(CredentialSystem)
	case s.IsZero():
		return "invalid"
	case s.IsAPIKey():
		return string(auth.CredentialAPIKey) + ":" + s.id
	}
	return string(s.subject) + ":" + s.id
}
