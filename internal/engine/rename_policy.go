package engine

import (
	"github.com/open-rails/authkit/iam"
)

// NamingPolicy returns the normalized site username policy.
func (s *Engine) NamingPolicy() iam.NamingPolicy { return s.cfg.namingPolicy }
