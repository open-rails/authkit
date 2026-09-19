package authkitfiber_test

import (
	"github.com/gofiber/fiber/v3"
	authkitfiber "github.com/open-rails/authkit/adapters/fiber"
	"github.com/open-rails/authkit/verify"
)

// Keep the adapter name source-compatible with shared types and function values.
var (
	_ authkitfiber.UserClaimsData                   = verify.UserClaimsData{}
	_ verify.UserClaimsData                         = authkitfiber.UserClaimsData{}
	_ func(fiber.Ctx) (verify.UserClaimsData, bool) = authkitfiber.UserClaims
)
