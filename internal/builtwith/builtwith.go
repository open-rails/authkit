// Package builtwith lets authtest read what a Client was built with, which
// the Client does not publish: a replica or a stale session of a Client the
// host built itself.
package builtwith

import "github.com/open-rails/authkit/internal/config"

// Of returns the Config and Deps an *authkit.Client was built with; false for
// anything else. The root package sets it.
var Of func(client any) (config.Config, config.Deps, bool)
