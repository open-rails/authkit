package authkitfiber

import (
	"github.com/gofiber/fiber/v3"
	"github.com/open-rails/authkit/iam"
)

// Error writes err as AuthKit's error envelope, with the catalog status for its
// code, and stops there: return it from the handler. A non-AuthKit error is
// written as 500 internal_error.
func Error(c fiber.Ctx, err error) error {
	w := newResponseWriter(c)
	iam.WriteError(w, err)
	w.flushHeaders()
	return nil
}
