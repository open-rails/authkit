package config

import (
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"slices"
	"strings"

	"github.com/open-rails/authkit/iam"
)

// ProvisioningTarget is one SCIM 2.0 service provider (RFC 7643, RFC 7644)
// AuthKit pushes the accounts to: each target receives every account and
// keeps it current. A change to what a SCIM User shows (email, username,
// display name, deletion, ban) is recorded in the change's transaction, which
// wakes a River job that sends the target its pending users' latest state in
// SCIM bulk requests; a failed push is retried, with backoff, when it is due.
// It needs Deps.Postgres and Start. A target removed from the list is
// forgotten, with its pending changes, when this issuer's River fleet starts.
type ProvisioningTarget struct {
	// TenantID is the canonical account owner sent to this target. An omitted
	// value uses Config.DefaultTenantID; an unbound deployment must set it.
	TenantID iam.TenantID `yaml:"tenant_id"`
	// Name identifies the target in its status and logs: 1-64 lowercase
	// letters, digits, '-' and '_'. Renaming a target makes a new one,
	// which gets a full initial sync.
	Name string `yaml:"name"`
	// URL is the SCIM base URL, beneath which /Users and /Bulk are served
	// ("https://billing.example.com/billing/v1/app/scim/v2"). Empty is an
	// in-process service provider: Deps.SCIMHandlers[Name].
	URL string `yaml:"url"`
	// BearerToken is a static credential sent as Authorization: Bearer.
	BearerToken string `yaml:"bearer_token"`
	// ClientID and ClientSecret get the access token with the OAuth 2.0
	// client-credentials grant (RFC 6749 §4.4) instead, for URL as the
	// resource (RFC 8707): the token endpoint and scopes come from URL's
	// protected-resource metadata (RFC 9728) and its authorization server's
	// metadata (RFC 8414).
	ClientID     string `yaml:"client_id"`
	ClientSecret string `yaml:"client_secret"`

	// invalid disables a misconfigured target: it stays registered, so its
	// pending changes wait for a fixed configuration.
	invalid error
}

// TargetInvalid is why Normalize disabled t; nil when t is usable.
func TargetInvalid(t ProvisioningTarget) error { return t.invalid }

var provisioningTargetName = regexp.MustCompile(`^[a-z0-9_-]{1,64}$`)

// normalizeProvisioning refuses targets without Deps.Postgres. A target with an
// invalid name is dropped; any other misconfigured one is disabled, keeping its
// pending changes, and a name declared twice disables both.
func normalizeProvisioning(targets []ProvisioningTarget, d Deps, degrade func(error)) ([]ProvisioningTarget, error) {
	if len(targets) == 0 {
		return nil, nil
	}
	if d.Postgres == nil {
		return nil, errors.New("authkit: Provisioning needs Deps.Postgres")
	}
	out := make([]ProvisioningTarget, 0, len(targets))
	for i, t := range targets {
		t.Name = strings.TrimSpace(t.Name)
		if !provisioningTargetName.MatchString(t.Name) {
			degrade(fmt.Errorf("authkit: Provisioning[%d]: invalid name %q (want 1-64 of a-z, 0-9, '-', '_'); it is ignored", i, t.Name))
			continue
		}
		if j := slices.IndexFunc(out, func(o ProvisioningTarget) bool { return o.Name == t.Name }); j >= 0 {
			if out[j].invalid == nil || !errors.Is(out[j].invalid, errDeclaredTwice) {
				out[j].invalid = fmt.Errorf("authkit: Provisioning target %q: %w", t.Name, errDeclaredTwice)
				degrade(out[j].invalid)
			}
			continue
		}
		if t.invalid == nil {
			if t.invalid = validProvisioningTarget(&t, d.SCIMHandlers[t.Name] != nil); t.invalid != nil {
				t.invalid = fmt.Errorf("authkit: Provisioning[%d] (%s): %w; its changes wait until it is fixed", i, t.Name, t.invalid)
				degrade(t.invalid)
			}
		}
		out = append(out, t)
	}
	return out, nil
}

var errDeclaredTwice = errors.New("declared twice; its changes wait until it is declared once")

func validProvisioningTarget(t *ProvisioningTarget, inProcess bool) error {
	t.URL = strings.TrimSuffix(strings.TrimSpace(t.URL), "/")
	switch {
	case (t.URL == "") != inProcess:
		return errors.New("set exactly one of URL and Deps.SCIMHandlers[Name]")
	case t.URL != "" && !httpURL(t.URL):
		return fmt.Errorf("URL %q must be an absolute http or https URL", t.URL)
	}
	t.ClientID = strings.TrimSpace(t.ClientID)
	switch {
	case (t.ClientID == "") != (t.ClientSecret == ""):
		return errors.New("set both ClientID and ClientSecret, or neither")
	case t.BearerToken != "" && t.ClientID != "":
		return errors.New("set at most one of BearerToken and ClientID")
	case t.ClientID != "" && t.URL == "":
		return errors.New("ClientID needs URL: its metadata names the token endpoint")
	}
	return nil

}

func httpURL(raw string) bool {
	u, err := url.Parse(raw)
	return err == nil && (u.Scheme == "https" || u.Scheme == "http") && u.Host != "" && u.Fragment == ""
}
