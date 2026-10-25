package notify

import (
	"errors"
	"testing"
	"time"
)

func TestWithdrawalUsesOnlyExactIdentityAndProducerRevision(t *testing.T) {
	mutation := Mutation{Input: Input{Recipient: Recipient{Audience: AudienceUser, ID: "user"},
		Origin: Origin{System: "contentkit", Scope: "app", ID: "comment.reply:B"}, Visibility: VisibilityApp, AppID: "app"},
		Revision: 2, Withdrawn: true}
	withdrawn, err := ValidateMutation(mutation)
	if err != nil || withdrawn.Origin != mutation.Origin || withdrawn.Revision != 2 {
		t.Fatalf("withdrawal requires an existing inbox item/payload: %+v %v", withdrawn, err)
	}
	mutation.Withdrawn = false
	if _, err := ValidateMutation(mutation); !errors.Is(err, ErrInvalid) {
		t.Fatalf("active publication accepted without payload metadata: %v", err)
	}
	mutation.Kind, mutation.CreatedAt = "comment.reply", time.Now()
	if _, err := ValidateMutation(mutation); err != nil {
		t.Fatal(err)
	}
	mutation.Revision = 0
	if _, err := ValidateMutation(mutation); !errors.Is(err, ErrInvalid) {
		t.Fatalf("unordered producer mutation accepted: %v", err)
	}
}
