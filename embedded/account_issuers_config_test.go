package embedded

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestAccountIssuersNormalization(t *testing.T) {
	cfg, err := normalizeConfig(Config{Token: TokenConfig{Issuer: " https://a.test ", AccountIssuers: []string{"https://b.test", " https://a.test", "https://b.test "}}})
	require.NoError(t, err)
	require.Equal(t, []string{"https://a.test", "https://b.test"}, cfg.Token.AccountIssuers, "own issuer first, trimmed and deduplicated")

	cfg, err = normalizeConfig(Config{Token: TokenConfig{Issuer: "https://solo.test"}})
	require.NoError(t, err)
	require.Equal(t, []string{"https://solo.test"}, cfg.Token.AccountIssuers)

	_, err = normalizeConfig(Config{Token: TokenConfig{Issuer: "https://a.test", AccountIssuers: []string{" "}}})
	require.ErrorContains(t, err, "blank issuer")
}
