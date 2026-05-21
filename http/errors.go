package authhttp

import (
	"encoding/json"
	"errors"
	"math"
	"net/http"
	"strconv"
	"time"

	core "github.com/open-rails/authkit/core"
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

func sendErrData(w http.ResponseWriter, status int, code string, data map[string]any) {
	if data == nil {
		sendErr(w, status, code)
		return
	}
	data["error"] = code
	writeJSON(w, status, data)
}

func badRequest(w http.ResponseWriter, code string)   { sendErr(w, http.StatusBadRequest, code) }
func unauthorized(w http.ResponseWriter, code string) { sendErr(w, http.StatusUnauthorized, code) }
func forbidden(w http.ResponseWriter, code string)    { sendErr(w, http.StatusForbidden, code) }
func tooMany(w http.ResponseWriter, retryAfter ...time.Duration) {
	if len(retryAfter) == 0 || retryAfter[0] <= 0 {
		sendErr(w, http.StatusTooManyRequests, "rate_limited")
		return
	}
	seconds := int(math.Ceil(retryAfter[0].Seconds()))
	if seconds < 1 {
		seconds = 1
	}
	w.Header().Set("Retry-After", strconv.Itoa(seconds))
	sendErrData(w, http.StatusTooManyRequests, "rate_limited", map[string]any{"retry_after_seconds": seconds})
}
func serverErr(w http.ResponseWriter, code string) { sendErr(w, http.StatusInternalServerError, code) }
func notFound(w http.ResponseWriter, code string)  { sendErr(w, http.StatusNotFound, code) }
func deliveryErr(w http.ResponseWriter, code string) {
	sendErr(w, http.StatusBadGateway, code)
}

func deliveryErrCode(err error) string {
	switch {
	case err == nil:
		return ""
	case errors.Is(err, core.ErrEmailDeliveryFailed):
		return "email_delivery_failed"
	case errors.Is(err, core.ErrSMSDeliveryFailed):
		return "sms_delivery_failed"
	default:
		return ""
	}
}
