package authhttp

import (
	"strings"

	"github.com/open-rails/authkit/oidckit"
)

type oidcConfig struct {
	Manager    *oidckit.Manager
	StateCache oidckit.StateCache
}

func (s *Service) oidcCfg() oidcConfig {
	return oidcConfig{
		Manager:    s.oidcManager(),
		StateCache: s.stateCache(),
	}
}

func joinRoutePath(prefix, path string) string {
	prefix = "/" + strings.Trim(strings.TrimSpace(prefix), "/")
	if prefix == "/" {
		prefix = ""
	}
	path = "/" + strings.Trim(strings.TrimSpace(path), "/")
	if path == "/" {
		path = ""
	}
	if prefix == "" && path == "" {
		return "/"
	}
	return prefix + path
}
