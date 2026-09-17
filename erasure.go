package authkit

import (
	"context"
	"errors"
	"time"
)

// Cross-site erasure handoff. Deployments sharing one account store
// (TokenConfig.AccountIssuers) each own data keyed by the account. A deletion
// raises one ErasureObligation with one acknowledgement per configured
// account issuer; purge removes the identity only once every issuer
// acknowledged, so a site that is offline or behind on its listing still
// receives the obligation first.

// ErasureObligation is one deleted account every account issuer must accept.
// It carries the identifiers hosts key on and outlives the users row.
type ErasureObligation struct {
	UserID      string
	Email       string // "" when the account had none
	Username    string
	PhoneNumber string
	CreatedAt   time.Time  // the deletion that raised the obligation
	PurgedAt    *time.Time // identity hard-deleted; nil while retained
}

// ErasureSiteBacklog is one site's unacknowledged obligations. It rides on
// GET {api}/admin/erasure/backlog.
type ErasureSiteBacklog struct {
	Site    string    `json:"site"`
	Pending int       `json:"pending"`
	Oldest  time.Time `json:"oldest_created_at"` // the age bound: oldest pending obligation
}

// ErasureAcceptFunc records one obligation durably in the host's own ledger
// (a committed row, not an in-flight erasure). Returning nil acknowledges it.
type ErasureAcceptFunc func(ctx context.Context, o ErasureObligation) error

// ErasureAcceptance reports one AcceptErasureObligations pass.
type ErasureAcceptance struct {
	Acknowledged int
	Failed       int
}

// AcceptErasureObligations drains every obligation pending for site: each is
// accepted then acknowledged, in pages of limit (0 = 500). A failed accept is
// left pending for the next pass and never blocks later pages. The joined
// failures are returned with the counts.
func AcceptErasureObligations(ctx context.Context, c Client, site string, limit int, accept ErasureAcceptFunc) (ErasureAcceptance, error) {
	var (
		out  ErasureAcceptance
		errs []error
		next string
	)
	for {
		page, cursor, err := c.ListErasureObligations(ctx, site, next, limit)
		if err != nil {
			return out, errors.Join(append(errs, err)...)
		}
		for _, o := range page {
			if err := accept(ctx, o); err != nil {
				out.Failed++
				errs = append(errs, err)
				continue
			}
			if err := c.AcknowledgeErasure(ctx, site, o.UserID); err != nil {
				out.Failed++
				errs = append(errs, err)
				continue
			}
			out.Acknowledged++
		}
		if cursor == "" {
			return out, errors.Join(errs...)
		}
		next = cursor
	}
}
