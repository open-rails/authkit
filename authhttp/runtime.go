package authhttp

import "github.com/open-rails/authkit/embedded"

type runtimeHTTP struct {
	*Service
	routes []embedded.HTTPRoute
}

func (s *runtimeHTTP) Routes() []embedded.HTTPRoute {
	return append([]embedded.HTTPRoute(nil), s.routes...)
}

// BuildHTTP implements embedded.HTTPConfiguration for a local Runtime. Hosts
// use runtime.ConfigureHTTP(config); construction and cleanup stay runtime-owned.
func (cfg Config) BuildHTTP(runtime *embedded.Runtime) (embedded.HTTPSurface, error) {
	// Freeze collection membership while retaining the host-owned provider objects.
	cfg.Documents = append([]DocumentProvider(nil), cfg.Documents...)
	cfg.Languages.Supported = append([]string(nil), cfg.Languages.Supported...)
	service, err := New(runtime, cfg)
	if err != nil {
		return nil, err
	}
	mount, err := NewMount(service, cfg.Mount)
	if err != nil {
		service.Close()
		return nil, err
	}
	surface := &runtimeHTTP{Service: service}
	for _, route := range mount.Routes() {
		surface.routes = append(surface.routes, embedded.HTTPRoute{Method: route.Method, Path: route.Path, Handler: mount})
	}
	return surface, nil
}
