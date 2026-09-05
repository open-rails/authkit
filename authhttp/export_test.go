package authhttp

import (
	"net/http"
	"net/http/httptest"

	"github.com/open-rails/authkit/verify"
)

// apiHandler serves the prefix-neutral JSON API routes at root and oidcHandler
// the browser OIDC routes under DefaultOIDCPath: test-only mux builders. Hosts
// mount through MountHandler.
func (s *Service) apiHandler() http.Handler {
	mux := http.NewServeMux()
	for _, route := range s.APIRoutes() {
		mux.Handle(route.Method+" "+route.Path, route.Handler)
	}
	return mux
}

func (s *Service) oidcHandler() http.Handler {
	mux := http.NewServeMux()
	for _, route := range s.OIDCBrowserRoutes() {
		mux.Handle(route.Method+" "+joinRoutePath(DefaultOIDCPath, route.Path), route.Handler)
	}
	return mux
}

// serveWithClaims serves h with cl (when non-nil) pre-attached to the request
// context, the way a Required gate would leave it.
func serveWithClaims(h http.Handler, cl *verify.Claims) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	if cl != nil {
		r = r.WithContext(verify.SetClaims(r.Context(), *cl))
	}
	h.ServeHTTP(w, r)
	return w
}
