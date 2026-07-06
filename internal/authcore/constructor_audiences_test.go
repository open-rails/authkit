package authcore

import "testing"

func TestExpectedAudiencesDefaultsToIssued(t *testing.T) {
	cfg := schemaTestConfig("")
	cfg.Token.IssuedAudiences = []string{"myapp", "billing"}
	cfg.Token.ExpectedAudiences = nil

	svc, err := NewFromConfig(cfg, nil)
	if err != nil {
		t.Fatal(err)
	}
	got := svc.Config().Token.ExpectedAudiences
	if len(got) != 2 || got[0] != "myapp" || got[1] != "billing" {
		t.Fatalf("ExpectedAudiences = %v, want [myapp billing]", got)
	}
	// Copied, not aliased.
	got[0] = "mutated"
	if cfg.Token.IssuedAudiences[0] != "myapp" {
		t.Fatal("ExpectedAudiences aliases IssuedAudiences")
	}
}

func TestExpectedAudiencesExplicitPreserved(t *testing.T) {
	cfg := schemaTestConfig("")
	cfg.Token.IssuedAudiences = []string{"myapp", "billing"}
	cfg.Token.ExpectedAudiences = []string{"myapp"}

	svc, err := NewFromConfig(cfg, nil)
	if err != nil {
		t.Fatal(err)
	}
	got := svc.Config().Token.ExpectedAudiences
	if len(got) != 1 || got[0] != "myapp" {
		t.Fatalf("ExpectedAudiences = %v, want [myapp]", got)
	}
}
