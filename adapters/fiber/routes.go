package authkitfiber

import (
	"errors"
	"github.com/gofiber/fiber/v3"
	"github.com/open-rails/authkit/embedded"
)

// Bundle contains the runtime's already configured route inventory.
type Bundle struct{ routes []embedded.HTTPRoute }

// Routes obtains the local runtime's HTTP surface without constructing a server,
// engine or additional HTTP state. ConfigureHTTP must precede this call.
func Routes(runtime *embedded.Runtime) (*Bundle, error) {
	routes, err := runtime.HTTPRoutes()
	if err != nil {
		return nil, err
	}
	return &Bundle{routes: routes}, nil
}

// Mount registers every configured route natively. AuthKit's JWKS, OIDC and
// document endpoints retain their required root anchors.
func (b *Bundle) Mount(target *fiber.App) error {
	if b == nil {
		return errors.New("authkitfiber: route bundle is required")
	}
	return mountHTTPRoutes(target, b.routes)
}
