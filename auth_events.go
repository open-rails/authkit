package authkit

import (
	"context"

	"github.com/open-rails/authkit/iam"
)

// ListEvents reads retained, committed changes in the selected tenant. The
// trusted host owns authorization, processing and cursor persistence. An
// explicit Authority query reads only authority-wide events, not every tenant.
// Reads register nothing and change no publisher state.
func (a *Client) ListEvents(ctx context.Context, q iam.EventQuery) (iam.EventPage, error) {
	return a.ops.ListEvents(a.operationContext(ctx), q)
}
