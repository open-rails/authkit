package authkit

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/open-rails/authkit/iam"
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
	base, err := url.Parse(cfg.BaseURL)
	if err != nil || base.Host == "" || (base.Scheme != "http" && base.Scheme != "https") || base.RawQuery != "" || base.Fragment != "" || base.User != nil {
		return nil, errors.New("authkit: remote base URL must be an absolute HTTP API URL without credentials, query or fragment")
	}
	client := cfg.HTTPClient
	if client == nil {
		client = http.DefaultClient
	}
	remote := &remoteEventReader{authority: cfg.Authority, base: strings.TrimRight(base.String(), "/"), client: client, headers: cfg.Headers.Clone()}
	return remote, nil
}

type remoteEventReader struct {
	authority bool
	base      string
	client    *http.Client
	headers   http.Header
}

var _ eventlog.Reader = (*remoteEventReader)(nil)

func (r *remoteEventReader) read(ctx context.Context, q iam.EventQuery) (iam.EventPage, error) {
	values := url.Values{}
	if q.After != "" {
		values.Set("after", q.After)
	}
	if q.Limit != 0 {
		values.Set("limit", strconv.Itoa(q.Limit))
	}
	if q.Authority {
		values.Set("authority", "true")
	}
	for _, t := range q.Types {
		values.Add("type", t)
	}
	for _, t := range q.Kinds {
		values.Add("kind", string(t))
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, r.base+"/events?"+values.Encode(), nil)
	if err != nil {
		return iam.EventPage{}, err
	}
	req.Header = r.headers.Clone()
	resp, err := r.client.Do(req)
	if err != nil {
		return iam.EventPage{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return iam.EventPage{}, iam.DecodeError(resp)
	}
	var page iam.EventPage
	if err := json.NewDecoder(resp.Body).Decode(&page); err != nil {
		return iam.EventPage{}, err
	}
	return page, nil
}

func (r *remoteEventReader) ListEvents(ctx context.Context, q eventlog.Query) (eventlog.Page, error) {
	q, err := eventlog.Normalize(q)
	if err != nil {
		return eventlog.Page{}, err
	}
	page, err := r.read(ctx, iam.EventQuery{After: q.After, Types: q.Types, Limit: q.Limit, Authority: r.authority})
	if err != nil {
		return eventlog.Page{}, err
	}
	return sharedEventPage(page)
}
