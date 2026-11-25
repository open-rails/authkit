package config

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/open-rails/authkit/internal/ident"
	"github.com/open-rails/authkit/notify"
)

// NotificationProducer is one source that publishes and withdraws its own
// notifications in the account inbox, in the tenant of the Client that
// registers it (Client.Notifications). Messages never select their own
// tenant, origin or visibility: the producer fixes them.
type NotificationProducer struct {
	// Name identifies it in its tenant: 1-64 of a-z, 0-9, '-' and '_',
	// starting with a letter.
	Name string
	// Origin is the system and scope its notifications come from.
	Origin notify.OriginScope
	// Visibility is notify.VisibilityApp (the default: this deployment's
	// inbox, by its Issuer) or notify.VisibilityTenant (every deployment of
	// the tenant).
	Visibility notify.Visibility
	// PermissionGroupID and Permission admit remote publication over HTTP
	// (POST {api}/notifications/{name}) by callers holding the concrete
	// Permission directly in that group; both empty is in-process only.
	PermissionGroupID string
	Permission        string
}

var notificationProducerName = regexp.MustCompile(`^[a-z][a-z0-9_-]{0,63}$`)

// NormalizeNotificationProducer checks p and defaults its visibility.
func NormalizeNotificationProducer(p NotificationProducer) (NotificationProducer, error) {
	if !ValidNotificationProducerName(p.Name) {
		return p, fmt.Errorf("authkit notifications: invalid producer name %q", p.Name)
	}
	if p.Visibility == "" {
		p.Visibility = notify.VisibilityApp
	}
	if p.Visibility != notify.VisibilityApp && p.Visibility != notify.VisibilityTenant {
		return p, fmt.Errorf("authkit notifications: producer %q needs an app or tenant visibility", p.Name)
	}
	if p.Origin.System == "" || strings.TrimSpace(p.Origin.System) != p.Origin.System || p.Origin.Scope == "" || strings.TrimSpace(p.Origin.Scope) != p.Origin.Scope {
		return p, fmt.Errorf("authkit notifications: producer %q needs an origin", p.Name)
	}
	if (p.PermissionGroupID == "") != (p.Permission == "") || p.Permission != "" && (ident.Perm(p.Permission).IsZero() || strings.Contains(p.Permission, "*")) {
		return p, fmt.Errorf("authkit notifications: producer %q needs both a permission group and concrete permission", p.Name)
	}
	return p, nil
}

// ValidNotificationProducerName is shared by registered and remote publishers.
func ValidNotificationProducerName(name string) bool {
	return notificationProducerName.MatchString(name)
}
