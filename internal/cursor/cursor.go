// Package cursor is AuthKit's one page-cursor codec: a keyset position as
// opaque base64url JSON. Clients pass cursors back verbatim; nothing outside
// this package reads their contents.
package cursor

import (
	"encoding/base64"
	"encoding/json"
	"errors"

	"github.com/open-rails/authkit/internal/errmodel"
)

// Encode makes an opaque cursor from a keyset position.
func Encode(position any) string {
	raw, err := json.Marshal(position)
	if err != nil {
		panic("cursor: unencodable position: " + err.Error())
	}
	return base64.RawURLEncoding.EncodeToString(raw)
}

// Decode reads a cursor made by Encode into position. A cursor that is not
// one is 400 invalid_request on param cursor.
func Decode(c string, position any) error {
	raw, err := base64.RawURLEncoding.DecodeString(c)
	if err == nil {
		err = json.Unmarshal(raw, position)
	}
	if err != nil {
		return Invalid()
	}
	return nil
}

// Keys decodes a cursor of n non-empty string keys; "" is the first page,
// all keys empty.
func Keys(c string, n int) ([]string, error) {
	if c == "" {
		return make([]string, n), nil
	}
	var keys []string
	if err := Decode(c, &keys); err != nil {
		return nil, err
	}
	if len(keys) != n {
		return nil, Invalid()
	}
	for _, k := range keys {
		if k == "" {
			return nil, Invalid()
		}
	}
	return keys, nil
}

// Invalid is the error for a cursor this deployment did not issue.
func Invalid() error {
	return errmodel.E(errmodel.CodeInvalidRequest, errmodel.WithParam("cursor"), errmodel.WithCause(errors.New("invalid page cursor")))
}
