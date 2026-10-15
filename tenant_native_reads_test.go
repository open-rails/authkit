package authkit_test

import (
	"github.com/open-rails/authkit"
	"github.com/open-rails/authkit/authtest"
	"github.com/open-rails/authkit/iam"
	"github.com/stretchr/testify/require"
	"testing"
)

func TestTenantNativeAccountDataRejectsForeignIDs(t *testing.T) {
	shared, _ := authtest.New(t, authtest.WithConfig(func(c *authkit.Config) { c.DefaultTenantID = iam.TenantID{}; c.DeviceKeys.Enabled = true }))
	views := make([]*authkit.Client, 2)
	users := make([]authtest.User, 2)
	for i := range views {
		id := iam.NewTenantID()
		require.NoError(t, shared.CreateTenant(t.Context(), iam.Tenant{ID: id}))
		var err error
		views[i], err = shared.ForTenant(t.Context(), id)
		require.NoError(t, err)
		users[i] = authtest.NewUser(t, views[i])
	}
	a, id := views[0], users[1].ID
	for _, test := range []struct {
		name string
		run  func() error
	}{
		{"agreements", func() error { _, err := a.UserAgreements(t.Context(), id); return err }},
		{"agreements due", func() error { _, err := a.AgreementsDue(t.Context(), id); return err }},
		{"accept agreements", func() error { return a.AcceptAgreements(t.Context(), id, nil) }},
		{"consents", func() error { _, err := a.OAuthConsents(t.Context(), id); return err }},
		{"revoke consent", func() error { return a.RevokeConsent(t.Context(), id, "foreign-client") }},
		{"sessions", func() error { _, err := a.Sessions(t.Context(), id); return err }},
		{"session events", func() error { _, err := a.ListSessionEvents(t.Context(), id, iam.SessionEventQuery{}); return err }},
		{"device keys", func() error { _, err := a.DeviceKeys(t.Context(), id); return err }},
	} {
		t.Run(test.name, func(t *testing.T) { require.ErrorIs(t, test.run(), iam.ErrUserNotFound) })
	}
}
