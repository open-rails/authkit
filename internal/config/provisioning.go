package config

import (
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/open-rails/authkit/iam"
)

// ProvisioningConfig pushes the accounts to SCIM 2.0 service providers
// (RFC 7643, RFC 7644): each target receives every account and keeps it
// current. A change to what a SCIM User shows (email, username, display
// name, deletion, ban) is recorded in the change's transaction, and every
// Interval a River job sends each target its pending users' latest state in
// SCIM bulk requests. It needs Deps.Postgres and Start.
type ProvisioningConfig struct {
	// Targets are the service providers. A target removed from the list is
	// forgotten, with its pending changes, when this issuer's River fleet
	// starts.
	Targets []ProvisioningTarget `yaml:"targets"`
	// Interval is how often the pending changes are sent; 0 defaults to five
	// minutes.
	Interval time.Duration `yaml:"interval"`
	// ReconcileInterval is how often each target's users are listed and
	// compared with the accounts, repairing what drifted; 0 defaults to a
	// day, and a negative value turns reconciliation off.
	ReconcileInterval time.Duration `yaml:"reconcile_interval"`
}

// ProvisioningTarget is one SCIM service provider: its base URL or an
// in-process handler, and how AuthKit authenticates to it.
type ProvisioningTarget struct {
	// TenantID is the canonical account owner sent to this target. An omitted
	// value uses Config.DefaultTenantID; an unbound deployment must set it.
	TenantID iam.TenantID `yaml:"tenant_id"`
	// Name identifies the target in its status and logs: 1-64 lowercase
	// letters, digits, '-' and '_'. Renaming a target makes a new one,
	// which gets a full initial sync.
	Name string `yaml:"name"`
	// URL is the SCIM base URL, beneath which /Users and /Bulk are served
	// ("https://billing.example.com/billing/v1/app/scim/v2").
	URL string `yaml:"url"`
	// Handler serves the SCIM endpoints in process instead of URL, so an
	// embedded service provider is called with no network. Requests reach it
	// with paths relative to the base ("/Users", "/Bulk").
	Handler http.Handler `yaml:"-"`
	// BearerToken is a static credential sent as Authorization: Bearer.
	BearerToken string `yaml:"bearer_token"`
	// ClientCredentials gets the access token from an OAuth 2.0 token
	// endpoint instead.
	ClientCredentials *ProvisioningClientCredentials `yaml:"client_credentials"`

	// invalid disables a misconfigured target: it stays registered, so its
	// pending changes wait for a fixed configuration.
	invalid error
}

// TargetInvalid is why Normalize disabled t; nil when t is usable.
func TargetInvalid(t ProvisioningTarget) error { return t.invalid }

// ProvisioningClientCredentials is an OAuth 2.0 client-credentials client
// (RFC 6749 §4.4) whose access tokens authenticate to a target.
type ProvisioningClientCredentials struct {
	TokenURL     string `yaml:"token_url"`
	ClientID     string `yaml:"client_id"`
	ClientSecret string `yaml:"client_secret"`
	// Scopes and Resource (RFC 8707) are sent with the token request when
	// set.
	Scopes   []string `yaml:"scopes"`
	Resource string   `yaml:"resource"`
}

// DefaultProvisioningInterval and DefaultProvisioningReconcileInterval are
// ProvisioningConfig's defaults.
const (
	DefaultProvisioningInterval          = 5 * time.Minute
	DefaultProvisioningReconcileInterval = 24 * time.Hour
)

var provisioningTargetName = regexp.MustCompile(`^[a-z0-9_-]{1,64}$`)

// normalizeProvisioning refuses targets without Deps.Postgres. A target with an
// invalid name is dropped; any other misconfigured one is disabled, keeping its
// pending changes, and a name declared twice disables both.
func normalizeProvisioning(p *ProvisioningConfig, d Deps, degrade func(error)) error {
	if len(p.Targets) == 0 {
		return nil
	}
	if d.Postgres == nil {
		return errors.New("authkit: Provisioning needs Deps.Postgres")
	}
	if p.Interval == 0 {
		p.Interval = DefaultProvisioningInterval
	}
	if p.Interval < time.Second {
		degrade(fmt.Errorf("authkit: Provisioning.Interval %s is under one second; using %s", p.Interval, DefaultProvisioningInterval))
		p.Interval = DefaultProvisioningInterval
	}
	switch {
	case p.ReconcileInterval == 0:
		p.ReconcileInterval = max(DefaultProvisioningReconcileInterval, p.Interval)
	case p.ReconcileInterval > 0 && p.ReconcileInterval < p.Interval:
		degrade(fmt.Errorf("authkit: Provisioning.ReconcileInterval %s is under Provisioning.Interval; using %s", p.ReconcileInterval, p.Interval))
		p.ReconcileInterval = p.Interval
	}
	targets := make([]ProvisioningTarget, 0, len(p.Targets))
	for i, t := range p.Targets {
		t.Name = strings.TrimSpace(t.Name)
		if !provisioningTargetName.MatchString(t.Name) {
			degrade(fmt.Errorf("authkit: Provisioning.Targets[%d]: invalid name %q (want 1-64 of a-z, 0-9, '-', '_'); it is ignored", i, t.Name))
			continue
		}
		if j := slices.IndexFunc(targets, func(o ProvisioningTarget) bool { return o.Name == t.Name }); j >= 0 {
			if targets[j].invalid == nil || !errors.Is(targets[j].invalid, errDeclaredTwice) {
				targets[j].invalid = fmt.Errorf("authkit: Provisioning target %q: %w", t.Name, errDeclaredTwice)
				degrade(targets[j].invalid)
			}
			continue
		}
		if t.invalid == nil {
			if t.invalid = validProvisioningTarget(&t); t.invalid != nil {
				t.invalid = fmt.Errorf("authkit: Provisioning.Targets[%d] (%s): %w; its changes wait until it is fixed", i, t.Name, t.invalid)
				degrade(t.invalid)
			}
		}
		targets = append(targets, t)
	}
	p.Targets = targets
	return nil
}

var errDeclaredTwice = errors.New("declared twice; its changes wait until it is declared once")

func validProvisioningTarget(t *ProvisioningTarget) error {
	t.URL = strings.TrimSuffix(strings.TrimSpace(t.URL), "/")
	switch {
	case (t.URL == "") == (t.Handler == nil):
		return errors.New("set exactly one of URL and Handler")
	case t.URL != "" && !httpURL(t.URL):
		return fmt.Errorf("URL %q must be an absolute http or https URL", t.URL)
	}
	if t.BearerToken != "" && t.ClientCredentials != nil {
		return errors.New("set at most one of BearerToken and ClientCredentials")
	}
	if cc := t.ClientCredentials; cc != nil {
		c := *cc
		c.TokenURL, c.ClientID, c.Resource = strings.TrimSpace(c.TokenURL), strings.TrimSpace(c.ClientID), strings.TrimSpace(c.Resource)
		if !httpURL(c.TokenURL) || c.ClientID == "" || c.ClientSecret == "" {
			return errors.New("ClientCredentials needs a TokenURL, ClientID and ClientSecret")
		}
		c.Scopes = slices.Clone(c.Scopes)
		t.ClientCredentials = &c
	}
	return nil
}

func httpURL(raw string) bool {
	u, err := url.Parse(raw)
	return err == nil && (u.Scheme == "https" || u.Scheme == "http") && u.Host != "" && u.Fragment == ""
}
