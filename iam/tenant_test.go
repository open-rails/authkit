package iam

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestTenantIDRoundTrip(t *testing.T) {
	id := NewTenantID()
	parsed, err := ParseTenantID(id.String())
	if err != nil || parsed != id || id.IsZero() {
		t.Fatal("tenant identity did not round trip", err)
	}

	for _, text := range []string{strings.ToUpper(id.String()), strings.ReplaceAll(id.String(), "-", ""), "{" + id.String() + "}", "urn:uuid:" + id.String()} {
		parsed, err := ParseTenantID(text)
		if err != nil || parsed != id {
			t.Fatalf("UUID format did not normalize: %q", text)
		}
	}
	if id[6]>>4 != 4 || id[8]>>6 != 2 {
		t.Fatal("generated tenant ID is not RFC4122 version4")
	}

	data, err := json.Marshal(id)
	if err != nil {
		t.Fatal(err)
	}
	var decoded TenantID
	if err := json.Unmarshal(data, &decoded); err != nil || decoded != id {
		t.Fatal("tenant wire identity did not round trip", err)
	}
	for _, bad := range []string{"", "tenant", "00000000-0000-0000-0000-000000000000"} {
		if _, err := ParseTenantID(bad); err == nil {
			t.Fatalf("accepted %q", bad)
		}
	}
}
