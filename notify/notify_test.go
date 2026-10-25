package notify

import (
	"errors"
	"testing"
	"time"
)

func TestValidateAllowsFutureKindsAndRejectsUnsafeShapes(t *testing.T) {
	base := Input{Recipient: Recipient{Audience: AudienceUser, ID: "user"}, Origin: Origin{System: "app", Scope: "tenant", ID: "event"}, Kind: "future.kind", CreatedAt: time.Now()}
	valid, err := Validate(base)
	if err != nil || string(valid.Data) != "{}" {
		t.Fatalf("extensible kind: %+v %v", valid, err)
	}
	for name, change := range map[string]func(*Input){"unknown audience": func(v *Input) { v.Recipient.Audience = "all" }, "empty origin": func(v *Input) { v.Origin.Scope = "" }, "NUL": func(v *Input) { v.Origin.ID = "a\x00b" }, "array": func(v *Input) { v.Data = []byte(`[]`) }, "null": func(v *Input) { v.Data = []byte(`null`) }, "resolved publish": func(v *Input) { v.Status = StatusResolved }} {
		t.Run(name, func(t *testing.T) {
			v := base
			change(&v)
			if _, err := Validate(v); !errors.Is(err, ErrInvalid) {
				t.Fatalf("invalid input accepted: %v", err)
			}
		})
	}
}
