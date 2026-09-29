package authhttp

import "github.com/open-rails/authkit"

type runtimeHTTP struct {
	*Service
	routes []authkit.HTTPRoute
}

func (s *runtimeHTTP) Routes() []authkit.HTTPRoute {
	return append([]authkit.HTTPRoute(nil), s.routes...)
}

// BuildHTTP implements authkit.HTTPConfiguration for a local Runtime. Hosts
// set authkit.Config.HTTP; construction and cleanup stay runtime-owned.
func (cfg Config) BuildHTTP(runtime authkit.HTTPBackend) (authkit.HTTPSurface, error) {
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
		surface.routes = append(surface.routes, authkit.HTTPRoute{Method: route.Method, Path: route.Path, Handler: mount})
	}
	return surface, nil
}
