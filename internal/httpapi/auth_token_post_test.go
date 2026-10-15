package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/internal/authflow"
	"github.com/open-rails/authkit/internal/errmodel"
)

type failedRefreshBackend struct {
	Backend
	err error
}

func (b failedRefreshBackend) ExchangeRefreshToken(context.Context, string, string, net.IP) (string, authflow.IssuedSession, error) {
	return "", authflow.IssuedSession{}, b.err
}

func TestRefreshErrorClassification(t *testing.T) {
	for _, tc := range []struct {
		name   string
		err    error
		status int
		code   string
	}{
		{"invalid", errmodel.E(errmodel.CodeInvalidToken), 401, "invalid_token"},
		{"revoked", errmodel.E(errmodel.CodeSessionRevoked), 401, "session_revoked"},
		{"banned", errmodel.ErrUserBanned, 401, "user_banned"},
		{"pool unavailable", errors.New("pool closed private details"), 500, "internal_error"},
		{"database timeout", fmt.Errorf("read session private details: %w", context.DeadlineExceeded), 500, "internal_error"},
		{"signer unavailable", errmodel.E(errmodel.CodeIssuerKeysUnavailable), 503, "issuer_keys_unavailable"},
		{"proof required", errmodel.E(errmodel.CodeSenderProofRequired), 401, "sender_proof_required"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := &Service{svc: failedRefreshBackend{err: tc.err}}
			r := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(`{"grant_type":"refresh_token","refresh_token":"secret-refresh"}`))
			r.Header.Set("Content-Type", "application/json")
			w := httptest.NewRecorder()
			s.handleAuthTokenPOST(w, r)
			require.Equal(t, tc.status, w.Code, w.Body.String())
			var envelope iam.ErrorEnvelope
			require.NoError(t, json.NewDecoder(w.Body).Decode(&envelope))
			require.Equal(t, tc.code, envelope.Error.Code)
			require.NotContains(t, w.Body.String(), "secret-refresh")
			require.NotContains(t, w.Body.String(), "private details")
			require.Empty(t, w.Result().Cookies())
		})
	}
}
