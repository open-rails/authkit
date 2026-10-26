package critical_test

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/open-rails/authkit"
	"github.com/open-rails/authkit/authtest"
	"github.com/open-rails/authkit/iam"
)

// A workload keeps acting for its user without the user's device: a renewable
// jwt-bearer client redeems one capability again, each time a whole grant.
func TestCriticalWorkloads(t *testing.T) {
	const resource = "https://hub.example"
	grants := &authtest.GrantAuthorizer{}
	jwtBearer := []authkit.OAuthGrantType{authkit.GrantJWTBearer}
	as := authtest.NewAuthorizationServer(t, authtest.WithConfig(func(c *authkit.Config) {
		c.DeviceKeys.Enabled = true
		c.TwoFactor.Mode = iam.TwoFactorDisabled
		c.AuthorizationServer = authkit.AuthorizationServerConfig{
			Resources: []authkit.ResourceServerConfig{{ID: resource}},
			Clients: []authkit.OAuthClientConfig{
				{ID: "renewing", Resources: []string{resource}, AuthorizationDetailsTypes: []string{"hub_read"}, GrantTypes: jwtBearer, RenewableCapabilities: true},
				{ID: "once", Resources: []string{resource}, AuthorizationDetailsTypes: []string{"hub_read"}, GrantTypes: jwtBearer},
			},
		}
	}), authtest.WithDeps(func(d *authkit.Deps) { d.OAuthGrants = grants.Authorize }))
	device := authtest.EnrollDeviceKey(t, as.Client, as.Outbox, authtest.NewUser(t, as.Client))
	workload := authtest.NewDPoPKey(t)
	reads := func(n int) string {
		entries := make([]string, n)
		for i := range entries {
			entries[i] = fmt.Sprintf(`{"type":"hub_read","commit":"c%d"}`, i)
		}
		return "[" + strings.Join(entries, ",") + "]"
	}
	capability := func(details string) string {
		return device.Capability(t, authtest.Capability{Audience: resource, Workload: workload, AuthorizationDetails: details})
	}
	refused := func(t *testing.T, want string, status int, body []byte) {
		t.Helper()
		var e struct{ Error, Reason string }
		if json.Unmarshal(body, &e) != nil || status != http.StatusBadRequest || e.Reason != want {
			t.Fatalf("want a %s refusal, got %d %s", want, status, body)
		}
	}

	t.Run("AK-J35-C01_a_renewable_capability_redeems_again_by_its_key_each_time_a_whole_grant", func(t *testing.T) {
		grants.Decide = func(iam.OAuthGrantRequest) (iam.OAuthGrantDecision, error) {
			return iam.OAuthGrantDecision{MaxLifetime: time.Minute}, nil
		}
		defer func() { grants.Decide = nil }()
		c := capability(reads(1))
		asked := len(grants.Requests())
		seen := map[string]bool{}
		for range 3 {
			got := as.JWTBearer(t, authtest.JWTBearerRequest{ClientID: "renewing", Key: workload, Capability: c})
			_, claims := jwtParts(t, got.AccessToken)
			cnf, _ := claims["cnf"].(map[string]any)
			if got.ExpiresIn < 55 || got.ExpiresIn > 60 || cnf["jkt"] != workload.Thumbprint() || seen[got.AccessToken] {
				t.Fatalf("a renewal is a new token bound to the workload for the authorizer's MaxLifetime: expires_in %d, cnf %v", got.ExpiresIn, cnf)
			}
			seen[got.AccessToken] = true
		}
		if n := len(grants.Requests()) - asked; n != 3 {
			t.Fatalf("the authorizer decided %d of 3 redemptions", n)
		}
		assertion := workload.Assertion(t, authtest.Assertion{Issuer: "renewing", Audience: as.TokenEndpoint(), Capability: c})
		as.JWTBearer(t, authtest.JWTBearerRequest{ClientID: "renewing", Key: workload, Assertion: assertion})
		status, body := as.JWTBearerToken(t, authtest.JWTBearerRequest{ClientID: "renewing", Key: workload, Assertion: assertion})
		refused(t, "assertion_replayed", status, body)
		status, body = as.JWTBearerToken(t, authtest.JWTBearerRequest{ClientID: "renewing", Key: authtest.NewDPoPKey(t), Capability: c})
		refused(t, "key_mismatch", status, body)
		once := capability(reads(1))
		as.JWTBearer(t, authtest.JWTBearerRequest{ClientID: "once", Key: workload, Capability: once})
		status, body = as.JWTBearerToken(t, authtest.JWTBearerRequest{ClientID: "once", Key: workload, Capability: once})
		refused(t, "capability_replayed", status, body)
	})

	t.Run("AK-J35-C02_a_capability_carries_up_to_64_operations", func(t *testing.T) {
		got := as.JWTBearer(t, authtest.JWTBearerRequest{ClientID: "renewing", Key: workload, Capability: capability(reads(64))})
		var details []json.RawMessage
		if json.Unmarshal(got.AuthorizationDetails, &details) != nil || len(details) != 64 {
			t.Fatalf("64 operations were not granted: %s", got.AuthorizationDetails)
		}
		status, body := as.JWTBearerToken(t, authtest.JWTBearerRequest{ClientID: "renewing", Key: workload, Capability: capability(reads(65))})
		refused(t, "capability_invalid", status, body)
	})

	t.Run("AK-J35-C03_renewal_ends_when_the_authorizer_refuses_or_the_device_key_is_revoked", func(t *testing.T) {
		c := capability(reads(1))
		as.JWTBearer(t, authtest.JWTBearerRequest{ClientID: "renewing", Key: workload, Capability: c})
		grants.Decide = func(iam.OAuthGrantRequest) (iam.OAuthGrantDecision, error) {
			return iam.OAuthGrantDecision{}, iam.ErrOAuthGrantRefused
		}
		status, body := as.JWTBearerToken(t, authtest.JWTBearerRequest{ClientID: "renewing", Key: workload, Capability: c})
		grants.Decide = nil
		refused(t, "refused", status, body)
		as.JWTBearer(t, authtest.JWTBearerRequest{ClientID: "renewing", Key: workload, Capability: c})
		authtest.RevokeDeviceKey(t, as.Client, device)
		status, body = as.JWTBearerToken(t, authtest.JWTBearerRequest{ClientID: "renewing", Key: workload, Capability: c})
		refused(t, "device_key_revoked", status, body)
	})
}
