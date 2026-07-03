// Experimental: NOT covered by the v1 semver contract (#202) — the standalone/
// remote transport has no production consumer yet; its surface (generated from
// authkit.Client) may change in MINOR releases until proven and promoted.
//
// Package remote is the AuthKit remote SDK: a Go client that talks to a standalone
// AuthKit server's management API over HTTP and satisfies the SAME
// authkit.Client contract an in-process embedded.Client does (#142), so a host
// swaps embedded↔remote with one construction line:
//
//	var c authkit.Client
//	c, _ = embedded.New(cfg, pg)        // in-process
//	c, _ = remote.New(baseURL, token)   // standalone, over HTTP
//	c.CreateUser(ctx, "a@b.com", "alice")
//
// Transport: every method marshals its arguments to the management API's generic
// POST /v1/call/{Method} contract (see authkit/server) and decodes {"result": ...}.
// Argument/result structs are shared with the server package (etcd's api/v3 model),
// so the two transports cannot drift. AuthKit sentinel errors are re-derived from
// the wire via authkit.ErrorForCode, so errors.Is(err, authkit.ErrX) holds across
// the network. Lean: net/http + encoding/json + the authkit contract only — no
// engine, no pgx.
package remote

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	authkit "github.com/open-rails/authkit"
)

// Client is a remote-backed AuthKit client. It satisfies authkit.Client; the
// compile-time assertion lives in conformance.go.
type Client struct {
	baseURL string
	token   string
	hc      *http.Client
}

// New builds a remote client for the management API at baseURL, authenticating
// with a static bearer token (the app→server credential; "" = none).
func New(baseURL, token string) *Client {
	return &Client{
		baseURL: strings.TrimRight(baseURL, "/"),
		token:   token,
		hc:      &http.Client{Timeout: 30 * time.Second},
	}
}

// WithHTTPClient overrides the underlying *http.Client (timeouts, transport, mTLS).
func (c *Client) WithHTTPClient(hc *http.Client) *Client {
	if hc != nil {
		c.hc = hc
	}
	return c
}

// call invokes a management method: POST /v1/call/{method} with args as the JSON
// body, decoding {"result": <out>} into out (out may be nil for void methods).
// A non-2xx response is mapped back to an AuthKit sentinel via errorForCode so
// errors.Is identity survives the wire.
func (c *Client) call(ctx context.Context, method string, args, out any) error {
	var body io.Reader
	if args != nil {
		b, err := json.Marshal(args)
		if err != nil {
			return err
		}
		body = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+"/v1/call/"+method, body)
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}
	resp, err := c.hc.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		var e struct {
			Error struct {
				Code string `json:"code"`
			} `json:"error"`
		}
		_ = json.NewDecoder(io.LimitReader(resp.Body, 1<<16)).Decode(&e)
		return errorForCode(e.Error.Code)
	}
	if out == nil {
		return nil
	}
	var env struct {
		Result json.RawMessage `json:"result"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&env); err != nil {
		return err
	}
	if len(env.Result) == 0 || string(env.Result) == "null" {
		return nil
	}
	return json.Unmarshal(env.Result, out)
}

// errorForCode re-derives an AuthKit sentinel from a wire error code via the
// shared authkit.ErrorForCode registry (one source of truth for client+server).
// Codes outside the contract surface as an opaque remote error.
func errorForCode(code string) error {
	if code == "" {
		return errors.New("remote: unknown error")
	}
	if e := authkit.ErrorForCode(code); e != nil {
		return e
	}
	return fmt.Errorf("remote: %s", code)
}
