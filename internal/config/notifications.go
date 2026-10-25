package config

import (
	"fmt"
	"maps"
	"regexp"
	"slices"
	"strings"

	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/internal/ident"
	"github.com/open-rails/helpers/notify"
)

// NotificationsConfig enables the account inbox. Nil leaves its schema and
// HTTP surface disabled. The schema uses the same PostgreSQL database as users.
type NotificationsConfig struct {
	Schema string `yaml:"schema"`
	// Scopes explicitly adopts existing inbox namespaces by canonical tenant ID.
	// Omitted tenants use authkit:<tenant UUID>. Two tenants cannot share a scope.
	Scopes map[string]string `yaml:"scopes"`
	// AppID fixes the HTTP inbox view to tenant-wide and this application's
	// receipts. Empty is the account-wide inbox; requests cannot override it.
	AppID string `yaml:"app_id"`
	// LegacyOrigins explicitly admits unclassified receipts during adoption.
	LegacyOrigins []notify.OriginScope `yaml:"legacy_origins"`
	// Producers are trusted, fixed publication bindings. The name selects one
	// binding; incoming messages never select their own tenant or source scope.
	Producers []NotificationProducer `yaml:"producers"`
}

// NotificationProducer authorizes one source to publish and withdraw its own
// exact notification identities in one account tenant.
type NotificationProducer struct {
	Name       string             `yaml:"name"`
	TenantID   iam.TenantID       `yaml:"tenant_id"`
	Origin     notify.OriginScope `yaml:"origin"`
	Visibility notify.Visibility  `yaml:"visibility"`
	AppID      string             `yaml:"app_id"`
	// PermissionGroupID and Permission enable authenticated remote publication.
	// Both empty leaves a trusted in-process-only producer. The permission must
	// be a declared, concrete permission on this group's persona.
	PermissionGroupID string `yaml:"permission_group_id"`
	Permission        string `yaml:"permission"`
}

var notificationProducerName = regexp.MustCompile(`^[a-z][a-z0-9_-]{0,63}$`)

func normalizeNotifications(c *Config) error {
	if c.Notifications == nil {
		return nil
	}
	n := *c.Notifications
	if n.Schema == "" {
		n.Schema = c.Database.Schema
	}
	schema, err := NormalizeSchema(n.Schema)
	if err != nil {
		return fmt.Errorf("authkit notifications: %w", err)
	}
	n.Schema = schema
	n.Scopes = maps.Clone(n.Scopes)
	seenScopes := map[string]bool{}
	for tenant, scope := range n.Scopes {
		id, err := iam.ParseTenantID(tenant)
		if err != nil || id.IsZero() || id.String() != tenant || scope == "" || strings.TrimSpace(scope) != scope || len(scope) > 512 || strings.ContainsRune(scope, 0) || seenScopes[scope] {
			return fmt.Errorf("authkit notifications: invalid or shared tenant inbox scope")
		}
		if strings.HasPrefix(scope, "authkit:") && scope != "authkit:"+tenant {
			return fmt.Errorf("authkit notifications: tenant scope cannot alias another canonical tenant")
		}
		seenScopes[scope] = true
	}
	n.LegacyOrigins = slices.Clone(n.LegacyOrigins)
	n.AppID = strings.TrimSpace(n.AppID)
	n.Producers = slices.Clone(n.Producers)
	names := map[string]bool{}
	for i := range n.Producers {
		p := &n.Producers[i]
		if p.TenantID.IsZero() {
			p.TenantID = c.DefaultTenantID
		}
		if p.TenantID.IsZero() {
			return fmt.Errorf("authkit notifications: producer %q needs a tenant", p.Name)
		}
		key := p.TenantID.String() + ":" + p.Name
		if !ValidNotificationProducerName(p.Name) || names[key] {
			return fmt.Errorf("authkit notifications: unique producer name per tenant required: %q", p.Name)
		}
		names[key] = true
		if p.Visibility == "" {
			p.Visibility = notify.VisibilityApp
		}
		if p.Visibility == notify.VisibilityApp && p.AppID == "" {
			p.AppID = n.AppID
		}
		if p.Visibility != notify.VisibilityApp && p.Visibility != notify.VisibilityTenant || p.Visibility == notify.VisibilityApp && p.AppID == "" || p.Visibility == notify.VisibilityTenant && p.AppID != "" {
			return fmt.Errorf("authkit notifications: producer %q needs a fixed app or tenant visibility", p.Name)
		}
		if p.Origin.System == "" || strings.TrimSpace(p.Origin.System) != p.Origin.System || p.Origin.Scope == "" || strings.TrimSpace(p.Origin.Scope) != p.Origin.Scope {
			return fmt.Errorf("authkit notifications: producer %q needs an origin", p.Name)
		}
		if (p.PermissionGroupID == "") != (p.Permission == "") || p.Permission != "" && (ident.Perm(p.Permission).IsZero() || strings.Contains(p.Permission, "*")) {
			return fmt.Errorf("authkit notifications: producer %q needs both a permission group and concrete permission", p.Name)
		}
	}
	c.Notifications = &n
	return nil
}

// NormalizeNotifications validates standalone notification migration settings.
// Producer tenants are already explicit when used without a complete Config.
func NormalizeNotifications(database DatabaseConfig, cfg *NotificationsConfig) (*NotificationsConfig, error) {
	c := Config{Database: database, Notifications: cfg}
	if err := normalizeNotifications(&c); err != nil {
		return nil, err
	}
	return c.Notifications, nil
}

// ValidNotificationProducerName is shared by configured and remote publishers.
func ValidNotificationProducerName(name string) bool {
	return notificationProducerName.MatchString(name)
}
