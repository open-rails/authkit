package authkit_test

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/open-rails/authkit"
	"github.com/open-rails/authkit/authtest"
	"github.com/open-rails/authkit/iam"
	"github.com/stretchr/testify/require"
)

// A message carries its language: the account's preference, else the
// request's (?lang, then Accept-Language, among the supported ones), else
// Languages.Default. Senders read it from the message, never from ctx.
func TestMessagesCarryTheirLanguage(t *testing.T) {
	auth, outbox := authtest.New(t, authtest.WithConfig(func(c *authkit.Config) {
		c.Languages = authkit.LanguageConfig{Supported: []string{"en", "es", "fr"}, Default: "fr"}
	}))
	u := authtest.NewUser(t, auth)
	reset := func(query, acceptLanguage string) string {
		t.Helper()
		r := httptest.NewRequest(http.MethodPost, "/api/v1/password/reset/request"+query, strings.NewReader(`{"identifier":"`+u.Email+`"}`))
		r.Header.Set("Content-Type", "application/json")
		if acceptLanguage != "" {
			r.Header.Set("Accept-Language", acceptLanguage)
		}
		w := httptest.NewRecorder()
		auth.Handler().ServeHTTP(w, r)
		require.Equal(t, http.StatusAccepted, w.Code, w.Body.String())
		return outbox.Last(t, iam.MessagePasswordReset, u.Email).Language
	}

	require.Equal(t, "fr", reset("", ""), "the default")
	require.Equal(t, "es", reset("", "de-DE, es-MX;q=0.8, en;q=0.5"), "the first supported Accept-Language entry")
	require.Equal(t, "fr", reset("", "de"), "an unsupported request language falls back to the default")
	require.Equal(t, "en", reset("?lang=EN_gb", "es"), "?lang wins over Accept-Language")

	preferred := "es"
	_, err := auth.UpdateUser(t.Context(), iam.SystemActor(), u.ID, iam.UserUpdate{PreferredLanguage: &preferred})
	require.NoError(t, err)
	require.Equal(t, "es", reset("?lang=en", "en"), "the account's preference wins")
}
