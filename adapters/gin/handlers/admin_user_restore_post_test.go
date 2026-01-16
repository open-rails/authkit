package handlers

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	core "github.com/PaulFidika/authkit/core"
	"github.com/gin-gonic/gin"
)

type stubRestoreProvider struct {
	core.Provider
	err error
}

func (s stubRestoreProvider) RestoreUser(ctx context.Context, userID string) error { return s.err }

func TestHandleAdminUserRestorePOST_NotFound(t *testing.T) {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.POST("/auth/admin/users/:user_id/restore", HandleAdminUserRestorePOST(stubRestoreProvider{err: core.ErrUserNotFound}, nil))
	req := httptest.NewRequest(http.MethodPost, "/auth/admin/users/u_123/restore", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", w.Code)
	}
}

func TestHandleAdminUserRestorePOST_OK(t *testing.T) {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.POST("/auth/admin/users/:user_id/restore", HandleAdminUserRestorePOST(stubRestoreProvider{err: nil}, nil))
	req := httptest.NewRequest(http.MethodPost, "/auth/admin/users/u_123/restore", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
}
