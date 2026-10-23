// Package remote implements AuthKit operations through the authority's HTTP
// routes. It is internal until the supported public-client surface is complete.
package remote

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/open-rails/authkit/auth"
	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/internal/actorconstraint"
)

// ErrActorProtocolUnsupported means the authority has no constrained-mutation
// endpoint. The client never retries an unconstrained endpoint.
var ErrActorProtocolUnsupported = errors.New("authkit: authority does not support expected-actor operations")

type Config struct {
	BaseURL    string
	HTTPClient *http.Client
	Headers    http.Header
}
type Client struct {
	base    string
	client  *http.Client
	headers http.Header
}

func New(cfg Config) (*Client, error) {
	base, err := url.Parse(cfg.BaseURL)
	if err != nil || base.Host == "" || (base.Scheme != "http" && base.Scheme != "https") || base.RawQuery != "" || base.Fragment != "" || base.User != nil {
		return nil, errors.New("authkit: remote base URL must be an absolute HTTP API URL without credentials, query or fragment")
	}
	client := cfg.HTTPClient
	if client == nil {
		client = http.DefaultClient
	}
	return &Client{base: strings.TrimRight(base.String(), "/"), client: client, headers: cfg.Headers.Clone()}, nil
}

func (c *Client) get(ctx context.Context, path string, query url.Values, out any) error {
	return c.request(ctx, http.MethodGet, path, query, nil, nil, out)
}

func (c *Client) request(ctx context.Context, method, path string, query url.Values, who *auth.Identity, body any, out any) error {
	var payload io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return err
		}
		payload = bytes.NewReader(b)
	}
	if who != nil {
		path = "/operations" + path
	}
	req, err := http.NewRequestWithContext(ctx, method, c.base+path+"?"+query.Encode(), payload)
	if err != nil {
		return err
	}
	req.Header = c.headers.Clone()
	if req.Header == nil {
		req.Header = make(http.Header)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if who != nil {
		req.Header.Set(actorconstraint.Header, actorconstraint.Encode(*who))
	}
	resp, err := c.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if err := iam.DecodeError(resp); err != nil {
		if who != nil && resp.StatusCode == http.StatusNotFound {
			detail, ok := iam.AsError(err)
			if !ok || detail.Code() == "" || detail.Code() == "not_found" {
				return fmt.Errorf("%w: %w", ErrActorProtocolUnsupported, err)
			}
		}
		return err
	}
	if out == nil {
		_, err = io.Copy(io.Discard, resp.Body)
		return err
	}
	decoder := json.NewDecoder(resp.Body)
	if err := decoder.Decode(out); err != nil {
		return err
	}
	// A successful response is one JSON value, not a partial response followed
	// by another payload or an error document.
	if err := decoder.Decode(new(any)); err != io.EOF {
		if err == nil {
			return errors.New("authkit: multiple remote response values")
		}
		return err
	}
	return nil
}
