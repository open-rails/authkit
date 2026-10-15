package authkit_test

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/open-rails/authkit"
	"github.com/open-rails/authkit/authtest"
	"github.com/open-rails/authkit/iam"
	"github.com/stretchr/testify/require"
)

func TestTenantIdentifierLimitsKeepGlobalAddressEnvelope(t *testing.T) {
	shared, _ := authtest.New(t, authtest.WithConfig(func(c *authkit.Config) {
		c.DefaultTenantID = iam.TenantID{}
		c.HTTP.RateLimits["password_reset_request"] = authkit.RateLimit{Limit: 1, Window: time.Hour}
	}))
	views := make([]*authkit.Client, 2)
	for i := range views {
		id := iam.NewTenantID()
		require.NoError(t, shared.CreateTenant(t.Context(), iam.Tenant{ID: id}))
		var err error
		views[i], err = shared.ForTenant(t.Context(), id)
		require.NoError(t, err)
	}
	request := func(client *authkit.Client, ip, email string) int {
		req := httptest.NewRequest(http.MethodPost, client.APIBase()+"/password/reset/request", strings.NewReader(`{"identifier":"`+email+`"}`))
		req.Header.Set("Content-Type", "application/json")
		req.RemoteAddr = ip + ":10000"
		w := httptest.NewRecorder()
		client.Handler().ServeHTTP(w, req)
		return w.Code
	}
	require.Equal(t, http.StatusAccepted, request(views[0], "203.0.113.1", "same@example.test"))
	require.Equal(t, http.StatusTooManyRequests, request(views[0], "203.0.113.2", "same@example.test"))
	require.Equal(t, http.StatusAccepted, request(views[1], "203.0.113.3", "same@example.test"), "another tenant has an independent identifier budget")
	require.Equal(t, http.StatusTooManyRequests, request(views[1], "203.0.113.4", "same@example.test"))
	require.Equal(t, http.StatusTooManyRequests, request(views[1], "203.0.113.1", "different@example.test"), "switching tenants must not reset the global client-address budget")
}
