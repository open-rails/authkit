package authhttp

import (
	"github.com/stretchr/testify/require"
	"testing"
)

type stepUpOptionsTestShape struct {
	Methods       []string `json:"methods"`
	DefaultMethod string   `json:"default_method"`
	Options       []struct {
		ID             string `json:"id"`
		Method         string `json:"method"`
		IsDefault      bool   `json:"is_default"`
		VerificationID string `json:"verification_id"`
	} `json:"options"`
}

func requireStepUp2FAOptions(t *testing.T, got stepUpOptionsTestShape, methods []string, defaultMethod string) {
	t.Helper()
	require.ElementsMatch(t, methods, got.Methods)
	require.Equal(t, defaultMethod, got.DefaultMethod)
	seen := map[string]bool{}
	for _, option := range got.Options {
		require.Empty(t, option.ID)
		require.NotEmpty(t, option.Method)
		seen[option.Method] = true
		if option.Method == defaultMethod {
			require.True(t, option.IsDefault)
		}
		if option.Method == "email" || option.Method == "sms" {
			require.NotEmpty(t, option.VerificationID)
		}
	}
	for _, method := range methods {
		require.True(t, seen[method], "missing 2FA option %q", method)
	}
}
