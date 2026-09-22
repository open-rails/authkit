package embedded

import (
	"errors"
	"net/http"

	"github.com/open-rails/authkit/verify"
)

// HTTPRoute is one fully anchored configured registration. Handler preserves
// AuthKit's canonical authentication and request-path processing.
type HTTPRoute struct {
	Method  string
	Path    string
	Handler http.Handler
}

// HTTPConfiguration constructs a local runtime's HTTP surface. authhttp.Config
// implements this small construction boundary without an embedded/authhttp
// package cycle. It is trusted host configuration, never a Client operation.
type HTTPConfiguration interface {
	BuildHTTP(HTTPBackend) (HTTPSurface, error)
}

// HTTPSurface is the runtime-owned result of local HTTP configuration.
type HTTPSurface interface {
	Routes() []HTTPRoute
	Verifier() *verify.Verifier
	Close()
}

// ConfigureHTTP configures HTTP once, after local provisioning and before
// obtaining routes. A failed build consumes the configuration attempt; the
// operation Client remains usable and Runtime.Close still releases its engine.
func (s *engine) ConfigureHTTP(cfg HTTPConfiguration) error {
	if s == nil {
		return errors.New("authkit: HTTP requires an initialized Runtime")
	}
	s.httpMu.Lock()
	defer s.httpMu.Unlock()
	if s.closed {
		return errors.New("authkit: Runtime is closed")
	}
	if s.httpFrozen {
		return errors.New("authkit: HTTP configuration is already sealed")
	}
	if cfg == nil {
		return errors.New("authkit: HTTP configuration is required")
	}
	s.httpFrozen = true
	surface, err := cfg.BuildHTTP(s)
	if err != nil {
		if surface != nil {
			surface.Close()
		}
		return err
	}
	if surface == nil {
		return errors.New("authkit: HTTP configuration returned no surface")
	}
	s.httpSurface = surface
	return nil
}

// HTTPRoutes returns the configured route inventory. Inspection seals HTTP
// configuration, including an unconfigured runtime; configure before mounting.
func (s *engine) HTTPRoutes() ([]HTTPRoute, error) {
	if s == nil {
		return nil, errors.New("authkit: HTTP requires an initialized Runtime")
	}
	s.httpMu.Lock()
	defer s.httpMu.Unlock()
	if s.closed {
		return nil, errors.New("authkit: Runtime is closed")
	}
	s.httpFrozen = true
	if s.httpSurface == nil {
		return nil, errors.New("authkit: HTTP is not configured; call Runtime.ConfigureHTTP first")
	}
	return append([]HTTPRoute(nil), s.httpSurface.Routes()...), nil
}

// Verifier returns the configured local HTTP verifier. It is nil before
// ConfigureHTTP or after Close. Ordinary verification remains stateless;
// callers select live verification explicitly for sensitive operations.
func (s *engine) Verifier() *verify.Verifier {
	if s == nil {
		return nil
	}
	s.httpMu.Lock()
	defer s.httpMu.Unlock()
	if s.closed || s.httpSurface == nil {
		return nil
	}
	return s.httpSurface.Verifier()
}
