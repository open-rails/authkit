package verify

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"strings"

	authkit "github.com/open-rails/authkit"
	"github.com/open-rails/authkit/documents"
)

var (
	errMalformedPayload = authkit.E(authkit.CodeMalformedPayload)
	errDuplicateClaim   = authkit.E(authkit.CodeDuplicateClaim)
)

// rawTopLevelClaim reads one claim off the already-signature-verified JWT
// payload strictly enough to preserve duplicate-key failures that MapClaims
// cannot.
func rawTopLevelClaim(token, key string) (json.RawMessage, bool, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, false, errMalformedPayload
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, false, errMalformedPayload
	}
	dec := json.NewDecoder(bytes.NewReader(payload))
	tok, err := dec.Token()
	if err != nil || tok != json.Delim('{') {
		return nil, false, errMalformedPayload
	}
	var raw json.RawMessage
	present := false
	for dec.More() {
		keyToken, err := dec.Token()
		if err != nil {
			return nil, false, errMalformedPayload
		}
		name, ok := keyToken.(string)
		if !ok {
			return nil, false, errMalformedPayload
		}
		var value json.RawMessage
		if err := dec.Decode(&value); err != nil {
			return nil, false, errMalformedPayload
		}
		if name == key {
			if present {
				return nil, true, errDuplicateClaim
			}
			present = true
			raw = value
		}
	}
	if tok, err = dec.Token(); err != nil || tok != json.Delim('}') {
		return nil, false, errMalformedPayload
	}
	if err := dec.Decode(&struct{}{}); err != io.EOF {
		return nil, false, errMalformedPayload
	}
	return raw, present, nil
}

// documentReferencesClaim parses the strict top-level `documents` claim.
func documentReferencesClaim(token string) (map[string]string, bool, error) {
	raw, present, err := rawTopLevelClaim(token, "documents")
	switch {
	case errors.Is(err, errDuplicateClaim):
		return nil, true, documents.ErrDuplicateReference
	case err != nil:
		return nil, false, documents.ErrInvalidReference
	case !present:
		return nil, false, nil
	}
	references, err := documents.ParseReferencesJSON(raw)
	return references, true, err
}
