package authhttp

import (
	"encoding/json"
	"net/http"
)

type errResp struct {
	Error string `json:"error"`
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func sendErr(w http.ResponseWriter, status int, code string) {
	writeJSON(w, status, errResp{Error: code})
}

func badRequest(w http.ResponseWriter, code string)   { sendErr(w, http.StatusBadRequest, code) }
func unauthorized(w http.ResponseWriter, code string) { sendErr(w, http.StatusUnauthorized, code) }
func forbidden(w http.ResponseWriter, code string)    { sendErr(w, http.StatusForbidden, code) }
func tooMany(w http.ResponseWriter)                   { sendErr(w, http.StatusTooManyRequests, "rate_limited") }
func serverErr(w http.ResponseWriter, code string)    { sendErr(w, http.StatusInternalServerError, code) }
func notFound(w http.ResponseWriter, code string)     { sendErr(w, http.StatusNotFound, code) }
