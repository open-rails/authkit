package iam

// DefaultPageLimit and MaxPageLimit bound PageRequest.Limit.
const (
	DefaultPageLimit = 50
	MaxPageLimit     = 500
)

// PageRequest asks for one page of a keyset-paged list. Limit 0 means
// DefaultPageLimit; larger values are capped at MaxPageLimit.
type PageRequest struct {
	Cursor string
	Limit  int
}

// PageLimit is the effective limit.
func (p PageRequest) PageLimit() int {
	switch {
	case p.Limit <= 0:
		return DefaultPageLimit
	case p.Limit > MaxPageLimit:
		return MaxPageLimit
	}
	return p.Limit
}

// ListPage is one page of a list. Next is the opaque cursor of the following
// page; "" marks the last page. Total, when the query asked for it, counts
// every item of the whole list.
type ListPage[T any] struct {
	Items []T    `json:"data"`
	Next  string `json:"next_cursor"`
	Total *int   `json:"total,omitempty"`
}
