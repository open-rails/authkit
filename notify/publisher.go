package notify

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// Publisher is the producer-facing account inbox channel. AuthKit binds its
// tenant, origin and application visibility when constructing the publisher.
// Each batch accepts at most MaxMutations exact identities. Retries reuse the
// producer's revision; older revisions never undo a newer publication or
// withdrawal. Producers do not read the inbox to decide what to publish.
//
// Omit tx to durably accept the batch in a new transaction. Supplying one
// non-nil transaction joins the batch to the producer's database mutation.
// Remote publishers enqueue delivery in their source database in both cases;
// successful acceptance does not require the destination to be online.
type Publisher interface {
	Publish(context.Context, []Publication, ...pgx.Tx) error
	Withdraw(context.Context, []Withdrawal, ...pgx.Tx) error
}

// Publication describes one user's current notification. ID is the exact
// deterministic producer ID, not a receipt ID or a wildcard pattern.
type Publication struct {
	RecipientID     string
	ID              string
	Revision        int64
	Kind            string
	Data            json.RawMessage
	CreatedAt       time.Time
	ActionRequested bool
	Severity        string
}

// Withdrawal hides one exact producer identity, including one not yet delivered.
// The retained revision prevents an older queued publication from reviving it.
type Withdrawal struct {
	RecipientID string
	ID          string
	Revision    int64
}

// ValidatePublication normalizes content before durable acceptance. The bound
// publisher supplies origin and visibility; recipients must be canonical account
// UUIDs, just as on the authenticated destination endpoint.
func ValidatePublication(in Publication) (Publication, error) {
	if err := ValidateWithdrawal(Withdrawal{RecipientID: in.RecipientID, ID: in.ID, Revision: in.Revision}); err != nil {
		return in, err
	}
	content, err := validateContent(Input{Kind: in.Kind, Data: in.Data, CreatedAt: in.CreatedAt, ActionRequested: in.ActionRequested, Severity: in.Severity})
	if err != nil {
		return in, err
	}
	in.Data = content.Data
	in.CreatedAt = content.CreatedAt.UTC().Truncate(time.Microsecond)
	return in, nil
}

// ValidateWithdrawal checks an exact producer identity and its durable revision.
func ValidateWithdrawal(in Withdrawal) error {
	id, err := uuid.Parse(in.RecipientID)
	if err != nil || id == uuid.Nil || id.String() != in.RecipientID || !validText(in.ID) || in.Revision < 1 {
		return fmt.Errorf("%w: canonical account ID, exact ID and positive revision required", ErrInvalid)
	}
	return nil
}
