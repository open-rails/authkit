package httpapi

import (
	"context"
	"encoding/json"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/internal/config"
	"github.com/open-rails/authkit/internal/naming"
	"github.com/stretchr/testify/require"
)

type usernameBackend struct{ Backend }

func (usernameBackend) AccountScope(context.Context) (iam.GroupRef, error) {
	return iam.GroupRef{}, iam.ErrTenantRequired
}

func (usernameBackend) CheckUsername(_ context.Context, name string) error {
	return naming.Validate(config.UsernameConfig{MinLength: 4, MaxLength: 30}, name)
}
func (usernameBackend) GenerateUsername(context.Context) (string, error) { return "naruto042", nil }
func TestUsernameEndpointsValidateBeforeAvailability(t *testing.T) {
	s := &Service{svc: usernameBackend{}}
	for _, value := range []string{"Paul Fidika", "Paul", "12paul"} {
		w := httptest.NewRecorder()
		s.handleUsernameAvailabilityGET(w, httptest.NewRequest("GET", "/usernames/availability?username="+url.QueryEscape(value), nil))
		require.Equal(t, 200, w.Code)
		var out AvailabilityField
		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &out))
		require.Equal(t, value == "Paul", out.Available)
		if value == "Paul Fidika" {
			require.NotNil(t, out.Error)
			require.Equal(t, "username_invalid_characters", *out.Error)
		}
	}
	w := httptest.NewRecorder()
	s.handleUsernameGenerateGET(w, httptest.NewRequest("GET", "/usernames/generate", nil))
	require.JSONEq(t, `{"username":"naruto042"}`, w.Body.String())
	require.Equal(t, "no-store", w.Header().Get("Cache-Control"))
}
