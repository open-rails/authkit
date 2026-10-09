package authflow

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"slices"
	"strconv"
)

// RFC 9396 authorization_details bounds, as requested and as decided.
const (
	MaxAuthorizationDetailsBytes = 8 << 10
	maxAuthorizationDetails      = 16
)

// ParseAuthorizationDetails validates an authorization_details parameter
// against the types a client declares: a JSON array of objects, each with
// one of those types. It returns the array re-encoded; nil for "".
func ParseAuthorizationDetails(raw string, allowed []string) (json.RawMessage, *OAuthError) {
	if raw == "" {
		return nil, nil
	}
	invalid := func(description string) (json.RawMessage, *OAuthError) {
		return nil, NewOAuthError(OAuthInvalidAuthorizationDetails, description)
	}
	if len(allowed) == 0 {
		return invalid("the client may not request authorization_details")
	}
	if len(raw) > MaxAuthorizationDetailsBytes {
		return invalid("authorization_details is too long")
	}
	_, types, err := authorizationDetails([]byte(raw))
	if err != nil {
		return invalid(err.Error())
	}
	for _, typ := range types {
		if !slices.Contains(allowed, typ) {
			return invalid("the client may not request authorization_details of type " + strconv.Quote(typ))
		}
	}
	return CompactAuthorizationDetails([]byte(raw))
}

// CompactAuthorizationDetails checks raw's shape and returns it re-encoded
// from what was checked: a repeated member keeps only the value read.
func CompactAuthorizationDetails(raw []byte) (json.RawMessage, *OAuthError) {
	if len(raw) > MaxAuthorizationDetailsBytes {
		return nil, NewOAuthError(OAuthInvalidAuthorizationDetails, "authorization_details is too long")
	}
	items, _, err := authorizationDetails(raw)
	if err != nil {
		return nil, NewOAuthError(OAuthInvalidAuthorizationDetails, err.Error())
	}
	out, err := json.Marshal(items)
	if err != nil {
		return nil, NewOAuthError(OAuthInvalidAuthorizationDetails, "authorization_details is not JSON")
	}
	return out, nil
}

// authorizationDetails checks the RFC 9396 §2 shape (a non-empty array of
// objects, each with a string type) and returns the objects and their types.
func authorizationDetails(raw []byte) ([]map[string]json.RawMessage, []string, error) {
	var items []map[string]json.RawMessage
	dec := json.NewDecoder(bytes.NewReader(raw))
	if err := dec.Decode(&items); err != nil || dec.More() {
		return nil, nil, errors.New("authorization_details must be a JSON array of objects")
	}
	if len(items) == 0 || len(items) > maxAuthorizationDetails {
		return nil, nil, fmt.Errorf("authorization_details must hold 1 to %d objects", maxAuthorizationDetails)
	}
	types := make([]string, 0, len(items))
	for _, item := range items {
		var typ string
		if item == nil || json.Unmarshal(item["type"], &typ) != nil || typ == "" {
			return nil, nil, errors.New("each authorization_details object needs a string type")
		}
		types = append(types, typ)
	}
	return items, types, nil
}

// NarrowsAuthorizationDetails reports whether every entry of narrowed is one
// of granted's, member order aside (numbers compare as written): a narrowing
// drops entries, never adds or changes one.
func NarrowsAuthorizationDetails(granted, narrowed json.RawMessage) bool {
	decode := func(raw json.RawMessage) ([]any, bool) {
		var items []any
		dec := json.NewDecoder(bytes.NewReader(raw))
		dec.UseNumber()
		return items, dec.Decode(&items) == nil
	}
	have, ok1 := decode(granted)
	want, ok2 := decode(narrowed)
	if !ok1 || !ok2 {
		return false
	}
	for _, w := range want {
		if !slices.ContainsFunc(have, func(h any) bool { return reflect.DeepEqual(h, w) }) {
			return false
		}
	}
	return true
}
