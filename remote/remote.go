// Package remote is the AuthKit remote SDK: a client that talks to a standalone
// AuthKit server's management API over HTTP, satisfying the same AuthKit
// capability interfaces an in-process embedded.Client does (#142). Lean — net/http
// + encoding/json only, no engine, no pgx.
//
// FIRST slice: authkit.Authorizer. remote.Client marshals each Authorizer call to
// the management API and re-derives AuthKit sentinel errors from the wire so
// errors.Is(err, authkit.ErrX) works across the network. The remaining
// authkit.Client methods grow the same way; this proves the transport.
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

// Client is a remote-backed AuthKit client.
type Client struct {
	baseURL string
	token   string
	hc      *http.Client
}

// New builds a remote client for the management API at baseURL, authenticating
// with a static bearer token (the app→server credential; "" = none).
func New(baseURL, token string) *Client {
	return &Client{baseURL: strings.TrimRight(baseURL, "/"), token: token, hc: &http.Client{Timeout: 30 * time.Second}}
}

// remote.Client satisfies the Authorizer slice today; the broad authkit.Client
// comes as the rest of the management API lands.
var _ authkit.Authorizer = (*Client)(nil)

func (c *Client) Can(ctx context.Context, subjectID, subjectKind, persona, instanceSlug, perm string) (bool, error) {
	var out struct {
		Allowed bool `json:"allowed"`
	}
	err := c.post(ctx, "/v1/authz/can", map[string]string{
		"subject_id": subjectID, "subject_kind": subjectKind,
		"persona": persona, "instance_slug": instanceSlug, "perm": perm,
	}, &out)
	return out.Allowed, err
}

func (c *Client) ListEffectivePermissions(ctx context.Context, subjectID, subjectKind, persona, instanceSlug string) ([]string, error) {
	var out struct {
		Values []string `json:"values"`
	}
	err := c.post(ctx, "/v1/authz/effective-permissions", map[string]string{
		"subject_id": subjectID, "subject_kind": subjectKind,
		"persona": persona, "instance_slug": instanceSlug,
	}, &out)
	return out.Values, err
}

func (c *Client) IsUserAllowed(ctx context.Context, userID string) (bool, error) {
	var out struct {
		Allowed bool `json:"allowed"`
	}
	err := c.post(ctx, "/v1/authz/user-allowed", map[string]string{"user_id": userID}, &out)
	return out.Allowed, err
}

func (c *Client) ListRoleSlugsByUserErr(ctx context.Context, userID string) ([]string, error) {
	var out struct {
		Values []string `json:"values"`
	}
	err := c.post(ctx, "/v1/authz/role-slugs", map[string]string{"user_id": userID}, &out)
	return out.Values, err
}

func (c *Client) post(ctx context.Context, path string, body, out any) error {
	b, err := json.Marshal(body)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+path, bytes.NewReader(b))
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
	return json.NewDecoder(resp.Body).Decode(out)
}

// errorForCode re-derives an AuthKit sentinel from a wire error code so
// errors.Is(err, authkit.ErrX) holds across the network. MVP registry keyed off
// each sentinel's own code; the FULL table (all 53 sentinels) is a #142 follow-up,
// ideally exposed as authkit.ErrorForCode so client+server share one map. (Note:
// authkit.ErrGroupNotFound's code is a human sentence, not snake_case — a wire-
// contract cleanup #142 should normalize.)
func errorForCode(code string) error {
	if code == "" {
		return errors.New("remote: unknown error")
	}
	if e, ok := codeErrors[code]; ok {
		return e
	}
	return fmt.Errorf("remote: %s", code)
}

var codeErrors = map[string]error{
	authkit.ErrUserNotFound.Error():     authkit.ErrUserNotFound,
	authkit.ErrUserBanned.Error():       authkit.ErrUserBanned,
	authkit.ErrGroupNotFound.Error():    authkit.ErrGroupNotFound,
	authkit.ErrNotGroupMember.Error():   authkit.ErrNotGroupMember,
	authkit.ErrUserRoleNotFound.Error(): authkit.ErrUserRoleNotFound,
}
