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

func decodeJSON(r *http.Request, dst any) error {
	if r == nil || r.Body == nil {
		return errors.New("missing_body")
	}
	dec := json.NewDecoder(r.Body)
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
