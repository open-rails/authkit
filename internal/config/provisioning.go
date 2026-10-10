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
	Targets []ProvisioningTarget
	// Interval is how often the pending changes are sent; 0 defaults to five
	// minutes.
	Interval time.Duration
	// ReconcileInterval is how often each target's users are listed and
	// compared with the accounts, repairing what drifted; 0 defaults to a
	// day, and a negative value turns reconciliation off.
	ReconcileInterval time.Duration
}

// ProvisioningTarget is one SCIM service provider: its base URL or an
// in-process handler, and how AuthKit authenticates to it.
type ProvisioningTarget struct {
	// Name identifies the target in its status and logs: 1-64 lowercase
	// letters, digits, '-' and '_'. Renaming a target makes a new one,
	// which gets a full initial sync.
	Name string
	// URL is the SCIM base URL, beneath which /Users and /Bulk are served
	// ("https://billing.example.com/billing/v1/app/scim/v2").
	URL string
	// Handler serves the SCIM endpoints in process instead of URL, so an
	// embedded service provider is called with no network. Requests reach it
	// with paths relative to the base ("/Users", "/Bulk").
	Handler http.Handler
	// BearerToken is a static credential sent as Authorization: Bearer.
	BearerToken string
	// ClientCredentials gets the access token from an OAuth 2.0 token
	// endpoint instead.
	ClientCredentials *ProvisioningClientCredentials
}

// ProvisioningClientCredentials is an OAuth 2.0 client-credentials client
// (RFC 6749 §4.4) whose access tokens authenticate to a target.
type ProvisioningClientCredentials struct {
	TokenURL     string
	ClientID     string
	ClientSecret string
	// Scopes and Resource (RFC 8707) are sent with the token request when
	// set.
	Scopes   []string
	Resource string
}

// DefaultProvisioningInterval and DefaultProvisioningReconcileInterval are
// ProvisioningConfig's defaults.
const (
	DefaultProvisioningInterval          = 5 * time.Minute
	DefaultProvisioningReconcileInterval = 24 * time.Hour
)

var provisioningTargetName = regexp.MustCompile(`^[a-z0-9_-]{1,64}$`)

func normalizeProvisioning(p *ProvisioningConfig, d Deps) error {
	if len(p.Targets) == 0 {
		return nil
	}
	if d.Postgres == nil {
		return errors.New("authkit: Provisioning needs Deps.Postgres")
	}
	switch {
	case p.Interval == 0:
		p.Interval = DefaultProvisioningInterval
	case p.Interval < time.Second:
		return errors.New("authkit: Provisioning.Interval must be at least one second")
	}
	switch {
	case p.ReconcileInterval == 0:
		p.ReconcileInterval = DefaultProvisioningReconcileInterval
	case p.ReconcileInterval > 0 && p.ReconcileInterval < p.Interval:
		return errors.New("authkit: Provisioning.ReconcileInterval must be at least Provisioning.Interval")
	}
	targets := make([]ProvisioningTarget, 0, len(p.Targets))
	for i, t := range p.Targets {
		t.Name = strings.TrimSpace(t.Name)
		if !provisioningTargetName.MatchString(t.Name) {
			return fmt.Errorf("authkit: Provisioning.Targets[%d]: invalid name %q (want 1-64 of a-z, 0-9, '-', '_')", i, t.Name)
		}
		if slices.ContainsFunc(targets, func(o ProvisioningTarget) bool { return o.Name == t.Name }) {
			return fmt.Errorf("authkit: Provisioning.Targets[%d]: target %q is declared twice", i, t.Name)
		}
		t.URL = strings.TrimSuffix(strings.TrimSpace(t.URL), "/")
		switch {
		case (t.URL == "") == (t.Handler == nil):
			return fmt.Errorf("authkit: Provisioning.Targets[%d] (%s): set exactly one of URL and Handler", i, t.Name)
		case t.URL != "" && !httpURL(t.URL):
			return fmt.Errorf("authkit: Provisioning.Targets[%d] (%s): URL %q must be an absolute http or https URL", i, t.Name, t.URL)
		}
		if t.BearerToken != "" && t.ClientCredentials != nil {
			return fmt.Errorf("authkit: Provisioning.Targets[%d] (%s): set at most one of BearerToken and ClientCredentials", i, t.Name)
		}
		if cc := t.ClientCredentials; cc != nil {
			c := *cc
			c.TokenURL, c.ClientID, c.Resource = strings.TrimSpace(c.TokenURL), strings.TrimSpace(c.ClientID), strings.TrimSpace(c.Resource)
			if !httpURL(c.TokenURL) || c.ClientID == "" || c.ClientSecret == "" {
				return fmt.Errorf("authkit: Provisioning.Targets[%d] (%s): ClientCredentials needs a TokenURL, ClientID and ClientSecret", i, t.Name)
			}
			c.Scopes = slices.Clone(c.Scopes)
			t.ClientCredentials = &c
		}
		targets = append(targets, t)
	}
	p.Targets = targets
	return nil
}

func httpURL(raw string) bool {
	u, err := url.Parse(raw)
	return err == nil && (u.Scheme == "https" || u.Scheme == "http") && u.Host != "" && u.Fragment == ""
}
