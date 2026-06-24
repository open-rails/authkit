package verify

import (
	"fmt"
	"sync"
	"testing"
)

// TestAddIssuer_LocalNotOverwritten pins AK-AUTH-01: a non-local registration may
// not overwrite a trusted local issuer, but a local re-registration (upsert) is
// allowed. Guards the slice→map refactor of the issuer registry.
func TestAddIssuer_LocalNotOverwritten(t *testing.T) {
	v := NewVerifier()
	const iss = "https://local.issuer"

	if err := v.AddIssuer(iss, []string{"aud"}, IssuerOptions{IsLocal: true}); err != nil {
		t.Fatalf("register local: %v", err)
	}
	// Non-local with the same id must be refused.
	if err := v.AddIssuer(iss, []string{"aud"}, IssuerOptions{IsLocal: false}); err == nil {
		t.Fatal("expected refusal overwriting local issuer with non-local registration")
	}
	ie := v.matchIssuer(iss)
	if ie == nil || !ie.isLocal {
		t.Fatalf("local issuer entry must be preserved, got %+v", ie)
	}
	// A local re-registration is a legitimate upsert.
	if err := v.AddIssuer(iss, []string{"aud2"}, IssuerOptions{IsLocal: true}); err != nil {
		t.Fatalf("local upsert should succeed: %v", err)
	}
	if ie := v.matchIssuer(iss); ie == nil || len(ie.audiences) != 1 || ie.audiences[0] != "aud2" {
		t.Fatalf("local upsert should have replaced audiences, got %+v", ie)
	}
}

// TestIssuerRegistry_ConcurrentAddRemoveMatch exercises the registry concurrently
// so the race detector validates the RWMutex + map. A stable local issuer must
// always resolve while other issuers churn.
func TestIssuerRegistry_ConcurrentAddRemoveMatch(t *testing.T) {
	v := NewVerifier()
	const stable = "https://stable.issuer"
	if err := v.AddIssuer(stable, []string{"aud"}, IssuerOptions{IsLocal: true}); err != nil {
		t.Fatalf("seed stable: %v", err)
	}

	var wg sync.WaitGroup
	const workers = 8
	const iters = 200
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			for i := 0; i < iters; i++ {
				id := fmt.Sprintf("https://tenant-%d-%d", w, i)
				_ = v.AddIssuer(id, []string{"aud"}, IssuerOptions{})
				if v.matchIssuer(stable) == nil {
					t.Errorf("stable issuer must always resolve")
					return
				}
				_ = v.matchIssuer(id)
				v.RemoveIssuer(id)
			}
		}(w)
	}
	wg.Wait()

	if v.matchIssuer(stable) == nil {
		t.Fatal("stable issuer lost after churn")
	}
}
