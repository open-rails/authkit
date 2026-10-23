// Package actorconstraint describes an expected actor, never an authority grant.
package actorconstraint

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"io"

	"github.com/open-rails/authkit/auth"
)

const Header = "AuthKit-Expected-Actor"

type actor struct {
	Issuer         string              `json:"issuer"`
	Tenant         string              `json:"tenant"`
	Subject        string              `json:"subject"`
	Kind           auth.SubjectKind    `json:"kind"`
	Invoker        auth.Invoker        `json:"invoker"`
	CredentialKind auth.CredentialKind `json:"credential_kind"`
	CredentialID   string              `json:"credential_id"`
}

func of(who auth.Identity) actor {
	return actor{who.Issuer, who.TenantID, who.Subject, who.SubjectKind, who.Invoker, who.Credential.Kind, who.Credential.ID}
}

// Encode drops credential state, roles and contact metadata. The server must
// authenticate independently and compare this precondition to that identity.
func Encode(who auth.Identity) string {
	b, _ := json.Marshal(of(who))
	return base64.RawURLEncoding.EncodeToString(b)
}
func Matches(raw string, who auth.Identity) bool {
	if len(raw) > 8192 {
		return false
	}
	b, err := base64.RawURLEncoding.DecodeString(raw)
	if err != nil {
		return false
	}
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	var expected actor
	return d.Decode(&expected) == nil && d.Decode(new(any)) == io.EOF && expected == of(who)
}
