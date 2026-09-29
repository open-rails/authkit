package authkitfiber_test

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gofiber/fiber/v3"
	authkitfiber "github.com/open-rails/authkit/adapters/fiber"
	"github.com/open-rails/authkit/iam"
	"github.com/stretchr/testify/require"
)

func TestErrorWritesEnvelope(t *testing.T) {
	for _, tc := range []struct {
		err    error
		status int
		code   string
	}{
		{fmt.Errorf("load owner: %w", iam.ErrUserNotFound), http.StatusNotFound, "user_not_found"},
		{errors.New("db down"), http.StatusInternalServerError, "internal_error"},
	} {
		app := fiber.New()
		app.Get("/x", func(c fiber.Ctx) error { return authkitfiber.Error(c, tc.err) })
		res, err := app.Test(httptest.NewRequest(http.MethodGet, "/x", nil))
		require.NoError(t, err)
		require.Equal(t, tc.status, res.StatusCode)
		require.Equal(t, "application/json", res.Header.Get("Content-Type"))
		var env iam.ErrorEnvelope
		require.NoError(t, json.NewDecoder(res.Body).Decode(&env))
		require.Equal(t, tc.code, env.Error.Code)
	}
}
