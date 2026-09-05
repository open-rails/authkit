package authhttp

import (
	"net/http"
	"sync"
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

// resetOIDCManagerForTest clears the lazy OIDC manager so a test can mutate
// providers after New.
func (s *Service) resetOIDCManagerForTest() {
	s.oidcMgrOnce = sync.Once{}
	s.oidcMgr = nil
}
