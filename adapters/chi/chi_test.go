package authkitchi

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/open-rails/authkit/authhttp"
	"github.com/stretchr/testify/require"
)

func TestRegisterRoutesSetsPathValues(t *testing.T) {
	router := chi.NewRouter()

	RegisterRoutes(router, "/api/v1", []authhttp.RouteSpec{{
		Method: http.MethodGet,
		Path:   "/namespaces/{slug}",
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, _ = w.Write([]byte(r.PathValue("slug")))
		}),
	}}, nil)

	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/v1/namespaces/cozy", nil))

	require.Equal(t, http.StatusOK, rec.Code)
	require.Equal(t, "cozy", rec.Body.String())
}
