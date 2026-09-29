package authkit

import (
	"github.com/open-rails/authkit/iam"
)

// NamingPolicy returns the normalized site policy for users and groups.
func (s *engine) NamingPolicy() iam.NamingPolicy { return s.cfg.namingPolicy }
