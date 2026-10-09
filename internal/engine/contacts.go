package engine

import (
	"context"
	"strings"

	"github.com/open-rails/helpers/contacts"

	"github.com/open-rails/authkit/internal/db"
)

// accountContact is how to reach u as the directory holds it: its verified
// email (an unproven address may be someone else's), and its username, which
// is also its display name. AuthKit keeps no other name.
func accountContact(u db.User) contacts.Contact {
	c := contacts.Contact{ID: u.ID, Username: deref(u.Username)}
	c.Name = c.Username
	if u.Email != nil && u.EmailVerified {
		c.Email = *u.Email
	}
	return c
}

// Contacts returns the live accounts among ids, keyed by id; a deleted,
// purged, unknown or malformed id is absent.
func (s *Engine) Contacts(ctx context.Context, ids []string) (map[string]contacts.Contact, error) {
	out := map[string]contacts.Contact{}
	if err := s.requirePG(); err != nil {
		return out, err
	}
	valid := make([]string, 0, len(ids))
	for _, id := range ids {
		if id, ok := canonicalUUID(id); ok {
			valid = append(valid, id)
		}
	}
	if len(valid) == 0 {
		return out, nil
	}
	users, err := s.q.UsersByIDs(ctx, valid)
	if err != nil {
		return nil, err
	}
	for _, u := range users {
		if u.DeletedAt == nil {
			out[u.ID] = accountContact(u)
		}
	}
	return out, nil
}

// SearchContacts returns up to limit live accounts whose verified email or
// username contains query, ignoring case.
func (s *Engine) SearchContacts(ctx context.Context, query string, limit int) ([]contacts.Contact, error) {
	out := []contacts.Contact{}
	if query == "" || limit < 1 {
		return out, nil
	}
	if err := s.requirePG(); err != nil {
		return out, err
	}
	users, err := s.q.ContactsSearch(ctx, db.ContactsSearchParams{Pattern: "%" + likeEscaper.Replace(strings.ToLower(query)) + "%", MaxRows: int64(min(limit, 1000))})
	if err != nil {
		return nil, err
	}
	for _, u := range users {
		out = append(out, accountContact(u))
	}
	return out, nil
}
