// Package server hosts the AuthKit management HTTP API — the wire contract a
// standalone AuthKit server exposes and the authkit/remote SDK consumes (#142).
//
// Transport: ONE generic dispatch endpoint, POST /v1/call/{Method}, where {Method}
// is a method name on authkit.Client. The request body is a JSON object of the
// method's named arguments; the response is {"result": <value>} on success or
// {"error": {"code": "<sentinel-code>"}} on failure. This is the etcd "one client,
// two transports" model (#138): handlers are defined ONCE over any authkit.Client
// (the embedded engine in-process, or a test fake), and authkit/remote marshals
// the SAME contract — so the two transports cannot drift the way two independent
// client implementations would.
//
// The method registry is assembled from per-capability slice maps (methods_*.go).
// Error identity survives the wire because the server emits the sentinel's code
// (err.Error()) and remote resolves it through authkit.ErrorForCode.
package server

import (
	"context"
	"encoding/json"
	"io"
	"net/http"

	authkit "github.com/open-rails/authkit"
)

// MethodFunc adapts one authkit.Client method to the wire: decode the JSON args,
// invoke the method, and return the result value (marshaled into {"result": ...}).
// A nil result with nil error encodes as {"result": null} (void methods).
type MethodFunc func(ctx context.Context, c authkit.Client, args json.RawMessage) (any, error)

// maxBody caps a management request body (1 MiB) — bootstrap manifests and bulk
// imports are the largest payloads; anything beyond this is rejected.
const maxBody = 1 << 20

// NewHandler serves the management API over the given AuthKit client, gated by a
// static bearer token ("" disables the gate — dev only). The handler dispatches
// POST /v1/call/{Method} through generatedMethods (see methods_gen.go, produced by
// `go generate ./...` from the authkit.Client interface).
func NewHandler(client authkit.Client, token string) http.Handler {
	reg := generatedMethods
	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/call/{method}", auth(token, func(w http.ResponseWriter, r *http.Request) {
		fn, ok := reg[r.PathValue("method")]
		if !ok {
			writeErr(w, http.StatusNotFound, "unknown_method")
			return
		}
		args, err := io.ReadAll(io.LimitReader(r.Body, maxBody))
		if err != nil {
			writeErr(w, http.StatusBadRequest, "invalid_request")
			return
		}
		result, err := fn(r.Context(), client, args)
		if err != nil {
			// Resolve the sentinel's wire code chain-aware (WRAPPED sentinels too),
			// so remote re-derives errors.Is identity. A non-sentinel is an opaque
			// server fault: emit a generic code, not err.Error() which could leak
			// internals (#197).
			code := authkit.CodeForError(err)
			if code == "" {
				code = "internal"
			}
			writeErr(w, statusFor(err), code)
			return
		}
		writeJSON(w, http.StatusOK, resultEnvelope{Result: result})
	}))
	return mux
}

// resultEnvelope is the success wire shape: {"result": <value>}.
type resultEnvelope struct {
	Result any `json:"result"`
}

// ErrorResponse is the failure wire shape. Code is the AuthKit sentinel's code
// (its .Error()), so remote re-derives errors.Is(err, authkit.ErrX) identity.
type ErrorResponse struct {
	Error struct {
		Code string `json:"code"`
	} `json:"error"`
}

// statusFor maps an error to an HTTP status. The CODE (not the status) carries
// error identity, so the mapping is coarse: a known AuthKit sentinel — matched
// chain-aware, so WRAPPED sentinels count too — is a client-side condition (422);
// anything else is a server fault (500).
func statusFor(err error) int {
	if authkit.CodeForError(err) != "" {
		return http.StatusUnprocessableEntity
	}
	return http.StatusInternalServerError
}

func auth(token string, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if token != "" && r.Header.Get("Authorization") != "Bearer "+token {
			writeErr(w, http.StatusUnauthorized, "unauthorized")
			return
		}
		next(w, r)
	}
}

// decodeArgs unmarshals the method's argument object. An empty body (no-arg
// methods) is treated as an empty object so the zero value is used.
func decodeArgs(raw json.RawMessage, v any) error {
	if len(raw) == 0 {
		return nil
	}
	return json.Unmarshal(raw, v)
}

func writeErr(w http.ResponseWriter, status int, code string) {
	var e ErrorResponse
	e.Error.Code = code
	writeJSON(w, status, e)
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
