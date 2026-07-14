package verify

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"io"
	"strings"

	"github.com/open-rails/authkit/documents"
)

// documentReferencesClaim reads the already-signature-verified JWT payload
// strictly enough to preserve duplicate-key failures that MapClaims cannot.
func documentReferencesClaim(token string) (map[string]string, bool, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, false, documents.ErrInvalidReference
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, false, documents.ErrInvalidReference
	}
	dec := json.NewDecoder(bytes.NewReader(payload))
	tok, err := dec.Token()
	if err != nil || tok != json.Delim('{') {
		return nil, false, documents.ErrInvalidReference
	}
	var raw json.RawMessage
	present := false
	for dec.More() {
		keyToken, err := dec.Token()
		if err != nil {
			return nil, false, documents.ErrInvalidReference
		}
		key, ok := keyToken.(string)
		if !ok {
			return nil, false, documents.ErrInvalidReference
		}
		var value json.RawMessage
		if err := dec.Decode(&value); err != nil {
			return nil, false, documents.ErrInvalidReference
		}
		if key == "documents" {
			if present {
				return nil, true, documents.ErrDuplicateReference
			}
			present = true
			raw = value
		}
	}
	if tok, err = dec.Token(); err != nil || tok != json.Delim('}') {
		return nil, false, documents.ErrInvalidReference
	}
	if err := dec.Decode(&struct{}{}); err != io.EOF {
		return nil, false, documents.ErrInvalidReference
	}
	if !present {
		return nil, false, nil
	}
	references, err := documents.ParseReferencesJSON(raw)
	return references, true, err
}
