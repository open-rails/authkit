package authhttp

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"testing"

	"github.com/stretchr/testify/require"
)

// shortAvailUsername returns a unique username within the 30-char registration
// limit: a short letter prefix plus the fast-changing tail of uniqueSuffix (which
// carries the per-call sequence counter, so each call is distinct).
func shortAvailUsername(prefix string) string {
	suffix := uniqueSuffix()
	if len(suffix) > 20 {
		suffix = suffix[len(suffix)-20:]
	}
	return prefix + suffix
}

// GET /register/availability used to answer username and email with TWO separate
// CheckPendingRegistrationConflict calls, each running the same
// UserEmailOrUsernameTaken query that already returns BOTH answers. #229 collapses
// them into ONE combined call covering every provided-and-valid identifier. This
// asserts the single call returns the correct taken/available answers for both
// fields, preserves the response shape, and runs the underlying query exactly
// once.
func TestRegisterAvailability_CombinedUsernameAndEmailSingleQuery(t *testing.T) {
	counter := newQueryCounter("UserEmailOrUsernameTaken")
	pool := newTracedServerTestPool(t, counter)
	ctx := context.Background()
	srv, err := NewServer(newServerClient(t, newServerTestConfig(), pool), WithoutRateLimiter())
	require.NoError(t, err)

	takenEmail := uniqueEmail("avail-taken")
	// Usernames are capped at 30 chars and must pass registration validation to
	// reach the conflict check, so keep them short (letter prefix + suffix tail).
	takenUsername := shortAvailUsername("avt")
	user, err := srv.svc.CreateUser(ctx, takenEmail, takenUsername)
	require.NoError(t, err)
	t.Cleanup(func() { _, _ = pool.Exec(ctx, `DELETE FROM profiles.users WHERE id=$1::uuid`, user.ID) })

	type field struct {
		Available bool   `json:"available"`
		Error     string `json:"error"`
	}
	type availabilityResponse struct {
		Username    *field `json:"username"`
		Email       *field `json:"email"`
		PhoneNumber *field `json:"phone_number"`
	}

	get := func(t *testing.T, username, email string) availabilityResponse {
		t.Helper()
		q := url.Values{}
		if username != "" {
			q.Set("username", username)
		}
		if email != "" {
			q.Set("email", email)
		}
		counter.arm()
		w := serveJSON(srv, http.MethodGet, "/register/availability?"+q.Encode(), "")
		counter.disarm()
		require.Equal(t, http.StatusOK, w.Code, w.Body.String())
		var resp availabilityResponse
		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
		return resp
	}

	// Headline dedup: a FRESH username and the TAKEN email are BOTH provided-and-
	// valid, so the single combined conflict query resolves both — username
	// available, email in-use. Before #229 this was TWO UserEmailOrUsernameTaken
	// executions (one per field's separate availability call); now it is one.
	freshUsername := shortAvailUsername("avf")
	resp := get(t, freshUsername, takenEmail)
	require.NotNil(t, resp.Username)
	require.True(t, resp.Username.Available)
	require.Empty(t, resp.Username.Error)
	require.NotNil(t, resp.Email)
	require.False(t, resp.Email.Available)
	require.Equal(t, "email_in_use", resp.Email.Error)
	require.Nil(t, resp.PhoneNumber, "phone_number omitted when not requested")
	require.Equal(t, 1, counter.count("UserEmailOrUsernameTaken"),
		"username+email availability must resolve in a single combined query")

	// Both fields free: one combined call still runs once and reports each as
	// available.
	resp = get(t, shortAvailUsername("avg"), uniqueEmail("avail-free"))
	require.NotNil(t, resp.Username)
	require.True(t, resp.Username.Available)
	require.Empty(t, resp.Username.Error)
	require.NotNil(t, resp.Email)
	require.True(t, resp.Email.Available)
	require.Empty(t, resp.Email.Error)
	require.Equal(t, 2, counter.count("UserEmailOrUsernameTaken"),
		"both-fields-provided still runs exactly one combined query")

	// Per-field behavior preserved: requesting only the email returns only the
	// email field (username/phone omitted), via a single combined call.
	resp = get(t, "", takenEmail)
	require.NotNil(t, resp.Email)
	require.False(t, resp.Email.Available)
	require.Equal(t, "email_in_use", resp.Email.Error)
	require.Nil(t, resp.Username, "username omitted when only email is requested")
	require.Nil(t, resp.PhoneNumber, "phone_number omitted when only email is requested")
	require.Equal(t, 3, counter.count("UserEmailOrUsernameTaken"))

	// A committed username is rejected at validation (owner_slug_taken) before the
	// conflict layer, so requesting only it runs NO conflict query — confirming the
	// combined call is skipped entirely when no field needs it.
	resp = get(t, takenUsername, "")
	require.NotNil(t, resp.Username)
	require.False(t, resp.Username.Available)
	require.Equal(t, "owner_slug_taken", resp.Username.Error)
	require.Nil(t, resp.Email)
	require.Equal(t, 3, counter.count("UserEmailOrUsernameTaken"),
		"a username rejected at validation triggers no conflict query")
}
