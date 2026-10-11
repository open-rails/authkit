package auth_test

import (
	"encoding/json"
	"testing"

	"github.com/open-rails/authkit/auth"
)

// A provider's credential state is opaque: encoding drops it, so an Identity
// rebuilt from data carries none, and only the provider reads it.
func TestCredentialStateIsNotEncoded(t *testing.T) {
	type bounds struct{ ceiling []string }
	state := &bounds{ceiling: []string{"merchant:payments:read"}}
	id := auth.Identity{Issuer: "https://host.example", Subject: "user-7", SubjectKind: auth.SubjectUser,
		Invoker: auth.Invoker{Issuer: "https://host.example", ID: "user-7"}, Credential: auth.Credential{Kind: auth.CredentialSession, ID: "s-1"}.WithState(state)}
	if id.Credential.State() != state {
		t.Fatal("the provider's state is lost")
	}
	b, err := json.Marshal(id)
	if err != nil {
		t.Fatal(err)
	}
	var decoded auth.Identity
	if err := json.Unmarshal(b, &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.Credential.State() != nil || decoded.Subject != id.Subject || decoded.Credential.ID != "s-1" {
		t.Fatalf("decoded = %+v", decoded)
	}
}

func TestSelfInvoked(t *testing.T) {
	self := auth.Identity{Issuer: "https://host.example", Subject: "app-1", SubjectKind: auth.SubjectApplication, Invoker: auth.Invoker{Issuer: "https://host.example", ID: "app-1"}}
	onBehalf := self
	onBehalf.Invoker = auth.Invoker{Issuer: "https://app.example", ID: "u_42"}
	if !self.SelfInvoked() || onBehalf.SelfInvoked() {
		t.Fatalf("self %v, on behalf %v", self.SelfInvoked(), onBehalf.SelfInvoked())
	}
}
