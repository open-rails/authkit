package authkit

import "github.com/open-rails/authkit/internal/config"

// Deps is everything AuthKit reaches outside the process through: the store,
// keys, identity providers, senders and the host's hooks, each a func.
type Deps = config.Deps
