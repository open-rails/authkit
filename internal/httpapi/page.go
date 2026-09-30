package httpapi

import (
	"net/http"
	"strconv"
	"strings"

	"github.com/open-rails/authkit/iam"
)

// pageQuery reads ?cursor= and ?limit= for a keyset-paged list.
func pageQuery(r *http.Request) iam.PageRequest {
	q := r.URL.Query()
	limit, _ := strconv.Atoi(q.Get("limit"))
	return iam.PageRequest{Cursor: strings.TrimSpace(q.Get("cursor")), Limit: limit}
}
