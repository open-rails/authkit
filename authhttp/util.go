package authhttp

import (
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"strings"
)

// maxRequestBodyBytes caps the size of a JSON request body we will read. Auth
// endpoints only ever carry small JSON payloads, so a 1 MiB ceiling is generous
// while preventing an unbounded body from exhausting memory (AK security audit F7).
const maxRequestBodyBytes = 1 << 20 // 1 MiB

func decodeJSON(r *http.Request, dst any) error {
	if r == nil || r.Body == nil {
		return errors.New("missing_body")
	}
	dec := json.NewDecoder(http.MaxBytesReader(nil, r.Body, maxRequestBodyBytes))
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		return err
	}
	// Reject trailing garbage.
	if err := dec.Decode(&struct{}{}); err != io.EOF {
		return errors.New("invalid_json")
	}
	return nil
}

func decodeOptionalJSON(r *http.Request, dst any) error {
	if r == nil || r.Body == nil || r.Body == http.NoBody {
		return nil
	}
	if r.ContentLength == 0 {
		return nil
	}
	return decodeJSON(r, dst)
}

func parseIP(s string) net.IP {
	if s == "" {
		return nil
	}
	// Allow "host:port" and plain host.
	if h, _, err := net.SplitHostPort(s); err == nil {
		s = h
	}
	return net.ParseIP(s)
}

// firstTrimmedNonEmpty returns the first value that is non-empty after TrimSpace,
// or "" if all are blank. Used to coalesce alternative request identifier fields
// (e.g. login/email/identifier) in caller-specified preference order.
func firstTrimmedNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v = strings.TrimSpace(v); v != "" {
			return v
		}
	}
	return ""
}
