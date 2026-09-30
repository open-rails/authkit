package iam

import (
	"encoding/json"
	"iter"
)

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
//
// On the wire it is {"data": [...], "next_cursor": string|null, "total":
// number|null}: the one list envelope.
type ListPage[T any] struct {
	Items []T
	Next  string
	Total *int
}

// All yields every item of a paged list, reading MaxPageLimit at a time:
// list reads the page it is given. The first error ends it, yielded with a
// zero item.
//
//	for m, err := range iam.All(func(p iam.PageRequest) (iam.ListPage[iam.Membership], error) {
//		return client.ListMemberships(ctx, subject, p)
//	}) {
func All[T any](list func(PageRequest) (ListPage[T], error)) iter.Seq2[T, error] {
	return func(yield func(T, error) bool) {
		p := PageRequest{Limit: MaxPageLimit}
		for {
			page, err := list(p)
			if err != nil {
				var zero T
				yield(zero, err)
				return
			}
			for _, item := range page.Items {
				if !yield(item, nil) {
					return
				}
			}
			if page.Next == "" {
				return
			}
			p.Cursor = page.Next
		}
	}
}

type listPageJSON[T any] struct {
	Data       []T     `json:"data"`
	NextCursor *string `json:"next_cursor"`
	Total      *int    `json:"total"`
}

func (p ListPage[T]) MarshalJSON() ([]byte, error) {
	out := listPageJSON[T]{Data: p.Items, Total: p.Total}
	if out.Data == nil {
		out.Data = []T{}
	}
	if p.Next != "" {
		out.NextCursor = &p.Next
	}
	return json.Marshal(out)
}

func (p *ListPage[T]) UnmarshalJSON(b []byte) error {
	var in listPageJSON[T]
	if err := json.Unmarshal(b, &in); err != nil {
		return err
	}
	*p = ListPage[T]{Items: in.Data, Total: in.Total}
	if in.NextCursor != nil {
		p.Next = *in.NextCursor
	}
	return nil
}
