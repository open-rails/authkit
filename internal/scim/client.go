package scim

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
)

// maxResponse caps what the client reads of one response.
const maxResponse = 32 << 20

// Client calls a SCIM service provider at Base (".../scim/v2") through HTTP,
// which carries the credential.
type Client struct {
	Base string
	HTTP *http.Client
}

// StatusError is a response with a status the call did not expect.
type StatusError struct {
	Status   int
	ScimType string
	Detail   string
}

func (e *StatusError) Error() string {
	msg := fmt.Sprintf("scim: HTTP %d", e.Status)
	if e.ScimType != "" {
		msg += " " + e.ScimType
	}
	if e.Detail != "" {
		msg += ": " + e.Detail
	}
	return msg
}

// IsStatus reports whether err is a StatusError with status.
func IsStatus(err error, status int) bool {
	var se *StatusError
	return errors.As(err, &se) && se.Status == status
}

// ErrorOf is the StatusError a failed operation's status and response
// describe.
func ErrorOf(status int, response []byte) *StatusError {
	e := &StatusError{Status: status}
	var body Error
	if json.Unmarshal(response, &body) == nil {
		e.ScimType, e.Detail = body.ScimType, body.Detail
	}
	return e
}

func (c *Client) do(ctx context.Context, method, path string, body any, want []int, out any) error {
	var reader io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return err
		}
		reader = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, strings.TrimSuffix(c.Base, "/")+path, reader)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", MediaType+", application/json")
	if body != nil {
		req.Header.Set("Content-Type", MediaType)
	}
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxResponse))
	if err != nil {
		return err
	}
	for _, status := range want {
		if resp.StatusCode == status {
			if out == nil || len(bytes.TrimSpace(raw)) == 0 {
				return nil
			}
			if err := json.Unmarshal(raw, out); err != nil {
				return fmt.Errorf("scim: %s %s: decode: %w", method, path, err)
			}
			return nil
		}
	}
	return ErrorOf(resp.StatusCode, raw)
}

// ServiceProviderConfig reads the provider's features and limits.
func (c *Client) ServiceProviderConfig(ctx context.Context) (ServiceProviderConfig, error) {
	var out ServiceProviderConfig
	err := c.do(ctx, http.MethodGet, "/ServiceProviderConfig", nil, []int{http.StatusOK}, &out)
	return out, err
}

// Bulk sends one bulk request; per-operation failures are in the response.
func (c *Client) Bulk(ctx context.Context, ops []BulkOperation) (BulkResponse, error) {
	var out BulkResponse
	err := c.do(ctx, http.MethodPost, "/Bulk", BulkRequest{Schemas: []string{SchemaBulkRequest}, Operations: ops}, []int{http.StatusOK}, &out)
	return out, err
}

// Create creates a user and returns it as stored, with the provider's id.
func (c *Client) Create(ctx context.Context, u User) (User, error) {
	var out User
	err := c.do(ctx, http.MethodPost, "/Users", u, []int{http.StatusCreated, http.StatusOK}, &out)
	return out, err
}

// Get reads the user id.
func (c *Client) Get(ctx context.Context, id string) (User, error) {
	var out User
	err := c.do(ctx, http.MethodGet, "/Users/"+url.PathEscape(id), nil, []int{http.StatusOK}, &out)
	return out, err
}

// Replace replaces the user id.
func (c *Client) Replace(ctx context.Context, id string, u User) error {
	return c.do(ctx, http.MethodPut, "/Users/"+url.PathEscape(id), u, []int{http.StatusOK, http.StatusNoContent}, nil)
}

// Delete deletes the user id; one already gone is no error.
func (c *Client) Delete(ctx context.Context, id string) error {
	err := c.do(ctx, http.MethodDelete, "/Users/"+url.PathEscape(id), nil, []int{http.StatusNoContent, http.StatusOK}, nil)
	if IsStatus(err, http.StatusNotFound) {
		return nil
	}
	return err
}

// List reads one page of users, startIndex 1-based.
func (c *Client) List(ctx context.Context, startIndex, count int) (ListResponse[User], error) {
	var out ListResponse[User]
	q := url.Values{"startIndex": {strconv.Itoa(startIndex)}, "count": {strconv.Itoa(count)}}
	err := c.do(ctx, http.MethodGet, "/Users?"+q.Encode(), nil, []int{http.StatusOK}, &out)
	return out, err
}

// FindByExternalID returns the provider's user whose externalId is id.
func (c *Client) FindByExternalID(ctx context.Context, id string) (User, bool, error) {
	var out ListResponse[User]
	q := url.Values{"filter": {`externalId eq ` + strconv.Quote(id)}}
	if err := c.do(ctx, http.MethodGet, "/Users?"+q.Encode(), nil, []int{http.StatusOK}, &out); err != nil {
		return User{}, false, err
	}
	for _, u := range out.Resources {
		if u.ExternalID == id {
			return u, true, nil
		}
	}
	return User{}, false, nil
}

// LocationID is the last path segment of a resource location.
func LocationID(location string) string {
	if u, err := url.Parse(location); err == nil {
		location = u.Path
	}
	location = strings.TrimSuffix(location, "/")
	if i := strings.LastIndex(location, "/"); i >= 0 {
		location = location[i+1:]
	}
	id, err := url.PathUnescape(location)
	if err != nil {
		return location
	}
	return id
}
