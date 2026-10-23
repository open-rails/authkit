package authkit

import (
	"context"
	"net/http"

	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/internal/remote"
	"github.com/open-rails/helpers/eventlog"
)

// RemoteEventConfig selects an existing HTTP API and its authenticated transport.
// BaseURL includes the API mount (for example https://auth.example/api/v1).
// Tenant routing and authentication are supplied by the host's HTTP transport
// or headers; no tenant identifier from an event cursor grants authority.
type RemoteEventConfig struct {
	BaseURL    string
	HTTPClient *http.Client
	Headers    http.Header
	Authority  bool
}

// NewRemoteEventReader builds the HTTP implementation of the shared event
// reader. It does not claim to provide AuthKit's other domain operations.
// Authority selects authority-wide events; HTTP still enforces permissions.
func NewRemoteEventReader(cfg RemoteEventConfig) (eventlog.Reader, error) {
	client, err := remote.New(remote.Config{BaseURL: cfg.BaseURL, HTTPClient: cfg.HTTPClient, Headers: cfg.Headers})
	if err != nil {
		return nil, err
	}
	return eventlog.ReaderFunc(func(ctx context.Context, q eventlog.Query) (eventlog.Page, error) {
		q, err := eventlog.Normalize(q)
		if err != nil {
			return eventlog.Page{}, err
		}
		page, err := client.ListEvents(ctx, iam.EventQuery{After: q.After, Types: q.Types, Limit: q.Limit, Authority: cfg.Authority})
		if err != nil {
			return eventlog.Page{}, err
		}
		return sharedEventPage(page)
	}), nil
}
