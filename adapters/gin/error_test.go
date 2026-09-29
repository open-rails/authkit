package authkitgin

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/open-rails/authkit/iam"
	"github.com/stretchr/testify/require"
)

func TestErrorWritesEnvelopeAndAborts(t *testing.T) {
	for _, tc := range []struct {
		err    error
		status int
		code   string
	}{
		{fmt.Errorf("load owner: %w", iam.ErrUserNotFound), http.StatusNotFound, "user_not_found"},
		{errors.New("db down"), http.StatusInternalServerError, "internal_error"},
	} {
		engine := gin.New()
		next := false
		engine.GET("/x", func(c *gin.Context) { Error(c, tc.err) }, func(*gin.Context) { next = true })
		w := httptest.NewRecorder()
		engine.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/x", nil))
		require.Equal(t, tc.status, w.Code)
		require.Equal(t, "application/json", w.Header().Get("Content-Type"))
		var env iam.ErrorEnvelope
		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &env))
		require.Equal(t, tc.code, env.Error.Code)
		require.False(t, next, "Error aborts the chain")
	}
}
