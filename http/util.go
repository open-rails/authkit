package authhttp

import (
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"strings"
)

func bearerToken(authorization string) string {
	if authorization == "" {
		return ""
	}
	parts := strings.SplitN(authorization, " ", 2)
	if len(parts) == 2 && strings.EqualFold(parts[0], "Bearer") {
		return parts[1]
	}
	return ""
}

// maxJSONBodyBytes bounds the request body any JSON endpoint will read. The
// auth endpoints (login, register, password reset, token, SIWS, ...) all decode
// through decodeJSON, so this is the single backstop that protects every
// embedder against an unbounded request body memory-exhaustion DoS. 1 MiB is far
// above any legitimate auth payload, including base64 SIWS signed messages.
const maxJSONBodyBytes int64 = 1 << 20

func decodeJSON(r *http.Request, dst any) error {
	if r == nil || r.Body == nil {
		return errors.New("missing_body")
	}
	// Cap the body before decoding. MaxBytesReader enforces the limit even with
	// a nil ResponseWriter (only the connection-abort optimization needs one),
	// which keeps decodeJSON's signature unchanged across its many callers.
	dec := json.NewDecoder(http.MaxBytesReader(nil, r.Body, maxJSONBodyBytes))
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		var tooLarge *http.MaxBytesError
		if errors.As(err, &tooLarge) {
			return errors.New("body_too_large")
		}
		return err
	}
	// Reject trailing garbage.
	if err := dec.Decode(&struct{}{}); err != io.EOF {
		return errors.New("invalid_json")
	}
	return nil
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
