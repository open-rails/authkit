package authkit

import (
	"encoding/json"
	"errors"
	"testing"
)

// #222: OpResult must round-trip its error as a sentinel wire code (#197) so
// errors.Is survives the remote transport; non-sentinel errors degrade to an
// opaque code; success stays nil.
func TestOpResultWireRoundTrip(t *testing.T) {
	in := []OpResult{
		{ID: "a"},
		{ID: "b", Err: ErrInsufficientRoleAuthority},
		{ID: "c", Err: errors.New("weird backend blowup")},
	}
	raw, err := json.Marshal(in)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var out []OpResult
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if out[0].Err != nil {
		t.Fatalf("success item gained an error: %v", out[0].Err)
	}
	if !errors.Is(out[1].Err, ErrInsufficientRoleAuthority) {
		t.Fatalf("sentinel did not survive the wire: %v", out[1].Err)
	}
	if out[2].Err == nil || out[2].Err.Error() != "internal_error" {
		t.Fatalf("non-sentinel should degrade to internal_error, got %v", out[2].Err)
	}
}
