package authkit

import (
	"context"

	"github.com/open-rails/helpers/contacts"
)

var _ contacts.Source = (*Client)(nil)

// Contacts returns how to reach the live accounts among ids, keyed by id, as
// they are now: the verified email (an unproven address may be someone
// else's) and the username, which is also the name. A deleted, unknown or
// malformed id is absent. Pass the Client as a library's contacts.Source.
func (a *Client) Contacts(ctx context.Context, ids []string) (map[string]contacts.Contact, error) {
	return a.ops.Contacts(ctx, ids)
}

// SearchContacts returns up to limit live accounts whose verified email or
// username contains query, ignoring case; query is literal text.
func (a *Client) SearchContacts(ctx context.Context, query string, limit int) ([]contacts.Contact, error) {
	return a.ops.SearchContacts(ctx, query, limit)
}
