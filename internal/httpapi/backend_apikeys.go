package httpapi

import (
	"context"
	"net/http"
	"strconv"
	"strings"

	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/verify"
)

// apiKeysBackend is API-key issuance and resolution.
type apiKeysBackend interface {
	APIKeys(ctx context.Context, ref iam.GroupRef, p iam.PageRequest) (iam.ListPage[iam.APIKey], error)
	MintAPIKey(ctx context.Context, a iam.Actor, ref iam.GroupRef, k iam.NewAPIKey) (iam.APIKey, string, error)
	RevokeAPIKey(ctx context.Context, a iam.Actor, ref iam.GroupRef, id string) (bool, error)
	verify.Enricher
}

// pageQuery reads ?cursor= and ?limit= for a keyset-paged list.
func pageQuery(r *http.Request) iam.PageRequest {
	q := r.URL.Query()
	limit, _ := strconv.Atoi(q.Get("limit"))
	return iam.PageRequest{Cursor: strings.TrimSpace(q.Get("cursor")), Limit: limit}
}
