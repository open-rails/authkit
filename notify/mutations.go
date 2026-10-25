package notify

import (
	"fmt"
	"time"
)

// MaxMutations bounds one atomic publication/withdrawal batch.
const MaxMutations = 100

// Mutation is the current state of one exact producer identity. The producer
// durably assigns Revision before delivery; transport retries reuse it. A newer
// publication replaces the payload, while Withdrawn hides the item even if it
// has not arrived yet. Neither IDs nor withdrawals interpret wildcards.
type Mutation struct {
	Input
	Revision  int64 `json:"revision"`
	Withdrawn bool  `json:"withdrawn,omitempty"`
}

// Adoption maps exact legacy origins for Current's recipient to one current
// producer identity during an explicit, stopped-writer migration. The host
// authorizes the mapping; it never means a prefix, range or inbox search.
type Adoption struct {
	Previous []Origin `json:"previous"`
	Current  Mutation `json:"current"`
}

// ValidateMutation validates and normalizes one producer mutation. Withdrawal
// needs only recipient, origin and visibility; payload fields are ignored.
func ValidateMutation(in Mutation) (Mutation, error) {
	if in.Revision < 1 {
		return in, fmt.Errorf("%w: positive producer revision required", ErrInvalid)
	}
	if !in.Withdrawn {
		var err error
		in.Input, err = Validate(in.Input)
		in.CreatedAt = in.CreatedAt.UTC().Truncate(time.Microsecond)
		return in, err
	}
	if err := validateIdentity(in.Input); err != nil {
		return in, err
	}
	in.Input = Input{Recipient: in.Recipient, Origin: Origin{System: in.Origin.System,
		Scope: in.Origin.Scope, ID: in.Origin.ID}, Visibility: in.Visibility, AppID: in.AppID}
	return in, nil
}
