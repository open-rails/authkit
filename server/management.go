// Package server hosts the AuthKit management HTTP API — the wire contract that a
// standalone AuthKit server exposes and the authkit/remote SDK consumes (#142).
//
// This is the FIRST slice: the Authorizer capability. The endpoints take an
// authkit.Authorizer (embedded.Client satisfies it, so does a remote-backed one),
// so the same handler works over the in-process engine. The full management API
// (all of authkit.Client) grows from here; the transport, auth seam, and
// error-identity round-trip are proven by this slice + remote's parity test.
package server

import (
	"encoding/json"
	"net/http"

	authkit "github.com/open-rails/authkit"
)

// Wire DTOs (the management-API JSON contract; remote/ agrees on these field names).
type CanRequest struct {
	SubjectID    string `json:"subject_id"`
	SubjectKind  string `json:"subject_kind"`
	Persona      string `json:"persona"`
	InstanceSlug string `json:"instance_slug"`
	Perm         string `json:"perm"`
}

type EffectivePermsRequest struct {
	SubjectID    string `json:"subject_id"`
	SubjectKind  string `json:"subject_kind"`
	Persona      string `json:"persona"`
	InstanceSlug string `json:"instance_slug"`
}

type UserIDRequest struct {
	UserID string `json:"user_id"`
}

type BoolResponse struct {
	Allowed bool `json:"allowed"`
}

type StringsResponse struct {
	Values []string `json:"values"`
}

// ErrorResponse is the wire error envelope. Code is the AuthKit sentinel's code
// (its .Error()), so remote can re-derive errors.Is(err, authkit.ErrX) identity.
type ErrorResponse struct {
	Error struct {
		Code string `json:"code"`
	} `json:"error"`
}

// NewAuthorizerHandler serves the Authorizer slice of the management API over the
// given authorizer, gated by a static bearer token ("" disables the gate — dev only).
func NewAuthorizerHandler(authz authkit.Authorizer, token string) http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("POST /v1/authz/can", auth(token, func(w http.ResponseWriter, r *http.Request) {
		var req CanRequest
		if !decode(w, r, &req) {
			return
		}
		ok, err := authz.Can(r.Context(), req.SubjectID, req.SubjectKind, req.Persona, req.InstanceSlug, req.Perm)
		writeBool(w, ok, err)
	}))

	mux.HandleFunc("POST /v1/authz/effective-permissions", auth(token, func(w http.ResponseWriter, r *http.Request) {
		var req EffectivePermsRequest
		if !decode(w, r, &req) {
			return
		}
		vals, err := authz.ListEffectivePermissions(r.Context(), req.SubjectID, req.SubjectKind, req.Persona, req.InstanceSlug)
		writeStrings(w, vals, err)
	}))

	mux.HandleFunc("POST /v1/authz/user-allowed", auth(token, func(w http.ResponseWriter, r *http.Request) {
		var req UserIDRequest
		if !decode(w, r, &req) {
			return
		}
		ok, err := authz.IsUserAllowed(r.Context(), req.UserID)
		writeBool(w, ok, err)
	}))

	mux.HandleFunc("POST /v1/authz/role-slugs", auth(token, func(w http.ResponseWriter, r *http.Request) {
		var req UserIDRequest
		if !decode(w, r, &req) {
			return
		}
		vals, err := authz.ListRoleSlugsByUserErr(r.Context(), req.UserID)
		writeStrings(w, vals, err)
	}))

	return mux
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

func decode(w http.ResponseWriter, r *http.Request, v any) bool {
	if err := json.NewDecoder(r.Body).Decode(v); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid_request")
		return false
	}
	return true
}

func writeBool(w http.ResponseWriter, ok bool, err error) {
	if err != nil {
		writeErr(w, http.StatusUnprocessableEntity, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, BoolResponse{Allowed: ok})
}

func writeStrings(w http.ResponseWriter, vals []string, err error) {
	if err != nil {
		writeErr(w, http.StatusUnprocessableEntity, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, StringsResponse{Values: vals})
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
