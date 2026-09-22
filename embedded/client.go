package embedded

import authkit "github.com/open-rails/authkit"

// clientView exposes only application operations, even to type assertions. It
// borrows the runtime; creating a view starts no resources or background work.
type clientView struct{ authkit.Client }

// Client returns the engine-free operation view. Runtime retains ownership of
// configuration, signing dependencies, HTTP and lifecycle.
func (s *engine) Client() authkit.Client {
	if s == nil {
		return nil
	}
	return clientView{Client: s}
}
