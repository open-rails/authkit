package httpapi

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/internal/config"
)

type cookieOwnershipBackend struct {
	Backend
	err error
}

var cookieOwnershipTenant = iam.TenantID{6: 0x40, 8: 0x80, 15: 1}

// These fixtures exercise a fixed tenant's legacy-cookie migration, not the
// central portal's active-tenant routing hint.
func (cookieOwnershipBackend) AccountScope(context.Context) (iam.GroupRef, error) {
	return iam.GroupByID(cookieOwnershipTenant.String()), nil
}

func cookieOwnershipService(err error) *Service {
	return &Service{svc: cookieOwnershipBackend{err: err}, cfg: config.Config{DefaultTenantID: cookieOwnershipTenant}}
}

func TestLegacyRefreshOwnershipOutageReturnsServerError(t *testing.T) {
	s := cookieOwnershipService(errors.New("database unavailable"))
	r := httptest.NewRequest("POST", "http://localhost/token", strings.NewReader(`{"grant_type":"refresh_token"}`))
	r.Header.Set("Content-Type", "application/json")
	r = r.WithContext(context.WithValue(r.Context(), refreshCookieCtxKey{}, refreshCookiePolicy{}))
	r.AddCookie(&http.Cookie{Name: "authkit_rt", Value: "owned"})
	w := httptest.NewRecorder()
	s.handleAuthTokenPOST(w, r)
	require.Equal(t, http.StatusInternalServerError, w.Code)
	require.Empty(t, w.Result().Cookies())
	require.NotContains(t, w.Body.String(), "invalid_token")
}

func (b cookieOwnershipBackend) OwnsRefreshToken(_ context.Context, token string) (bool, error) {
	return token == "owned", b.err
}

func TestLegacyRefreshOwnershipSelection(t *testing.T) {
	for _, outage := range []bool{false, true} {
		s := cookieOwnershipService(nil)
		if outage {
			s.svc = cookieOwnershipBackend{err: errors.New("database unavailable")}
		}
		r := httptest.NewRequest("POST", "http://localhost/token", nil)
		r = r.WithContext(context.WithValue(r.Context(), refreshCookieCtxKey{}, refreshCookiePolicy{}))
		r.AddCookie(&http.Cookie{Name: "authkit_rt", Value: "foreign"})
		r.AddCookie(&http.Cookie{Name: "__Host-authkit_rt", Value: "owned"})
		token, ok, err := s.refreshTokenFromRequest(r, "")
		w := httptest.NewRecorder()
		s.clearRefreshCookie(w, r)
		if outage {
			require.Error(t, err)
			require.False(t, ok)
		} else {
			require.NoError(t, err)
			require.True(t, ok)
			require.Equal(t, "owned", token)
		}
		for _, c := range w.Result().Cookies() {
			require.NotEqual(t, "authkit_rt", c.Name, "foreign legacy cookie was cleared")
			if outage {
				require.NotEqual(t, "__Host-authkit_rt", c.Name, "outage cleared legacy cookie")
			}
		}
	}
}
