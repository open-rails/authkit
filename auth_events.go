package authkit

import (
	"context"
	"encoding/json"
	"github.com/open-rails/helpers/eventlog"

	"github.com/open-rails/authkit/iam"
)

// ListEvents reads retained, committed changes in the selected tenant. The
// trusted host owns authorization, processing and cursor persistence. An
// explicit Authority query reads only authority-wide events, not every tenant.
// Reads register nothing and change no publisher state.
func (a *Client) ListEvents(ctx context.Context, q iam.EventQuery) (iam.EventPage, error) {
	return a.ops.ListEvents(a.operationContext(ctx), q)
}

// EventReader adapts the selected client's event facade to the shared reader.
// The optional authority flag selects authority-wide events instead of tenant
// events. Remote requests still undergo the authority's normal authorization.
func (a *Client) EventReader(authority ...bool) eventlog.Reader {
	return eventlog.ReaderFunc(func(ctx context.Context, q eventlog.Query) (eventlog.Page, error) {
		normalized, err := eventlog.Normalize(q)
		if err != nil {
			return eventlog.Page{}, err
		}
		query := iam.EventQuery{After: normalized.After, Types: normalized.Types, Limit: normalized.Limit}
		if len(authority) > 0 {
			query.Authority = authority[0]
		}
		page, err := a.ListEvents(ctx, query)
		if err != nil {
			return eventlog.Page{}, err
		}
		return sharedEventPage(page)
	})
}

func sharedEventPage(page iam.EventPage) (eventlog.Page, error) {
	out := eventlog.Page{Events: []eventlog.Event{}, NextCursor: page.NextCursor, HasMore: page.HasMore, RetentionSeconds: page.RetentionSeconds}
	for _, event := range page.Events {
		if event.Type == "" {
			event.Type = event.Kind
		}
		event.OccurredAt = event.OccurredAt.UTC()
		event.RecordedAt = event.RecordedAt.UTC()
		data, err := json.Marshal(event)
		if err != nil {
			return eventlog.Page{}, err
		}
		scope := event.TenantID.String()
		if scope == "" {
			scope = "authority"
		}
		subject := eventlog.Subject{}
		switch {
		case event.UserID != "":
			subject = eventlog.Subject{Type: "user", ID: event.UserID}
		case event.ApplicationID != "":
			subject = eventlog.Subject{Type: "application", ID: event.ApplicationID}
		case event.GroupID != "":
			subject = eventlog.Subject{Type: "group", ID: event.GroupID}
		}
		out.Events = append(out.Events, eventlog.Event{ID: event.ID, Source: "authkit", Scope: scope, Type: string(event.Type), Version: event.Version, OccurredAt: event.OccurredAt, RecordedAt: event.RecordedAt, Subject: subject, Data: data})
	}
	return out, nil
}
