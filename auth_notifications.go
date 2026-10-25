package authkit

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/internal/engine"
	"github.com/open-rails/helpers/notify"
	notifypg "github.com/open-rails/helpers/notify/postgres"
)

// ErrNotificationsDisabled means the optional account inbox is not configured.
var ErrNotificationsDisabled = engine.ErrNotificationsDisabled

// ErrNotificationScopeConflict refuses inconsistent account-inbox ownership.
var ErrNotificationScopeConflict = engine.ErrNotificationScopeConflict

// Notifications returns the declared producer's fixed-tenant publisher. Pass
// it to ContentKit, OpenRails or application code. Its transaction method must
// use the account database; it never opens another transaction behind the caller.
func (a *Client) Notifications(producer string) (notifypg.TxSink, error) {
	if a == nil || a.engine == nil {
		return nil, errors.New("authkit: notification publisher needs a client")
	}
	p, err := a.engine.NotificationProducer(a.operationContext(context.Background()), producer)
	if err != nil {
		return nil, err
	}
	return &accountNotificationPublisher{engine: a.engine, tenant: p.TenantID, producer: producer}, nil
}

type accountNotificationPublisher struct {
	engine   *engine.Engine
	tenant   iam.TenantID
	producer string
}

func (p *accountNotificationPublisher) Apply(ctx context.Context, changes []notify.Mutation) error {
	return p.engine.ApplyNotifications(engine.WithTenant(ctx, p.tenant), p.producer, changes)
}
func (p *accountNotificationPublisher) ApplyTx(ctx context.Context, tx pgx.Tx, changes []notify.Mutation) error {
	return p.engine.ApplyNotificationsTx(engine.WithTenant(ctx, p.tenant), tx, p.producer, changes)
}

// NotificationScope is the durable namespace of this client's account tenant.
// It allows required erasure/recovery integrations to retain the same fences
// while inbox ownership moves from an application to AuthKit.
func (a *Client) NotificationScope() (string, error) {
	return a.engine.NotificationScope(a.operationContext(context.Background()))
}

// ListNotifications is a trusted native account-inbox read. HTTP always derives
// userID from the current session and never accepts a recipient selector.
func (a *Client) ListNotifications(ctx context.Context, userID string, options notify.ListOptions) (notify.Page, error) {
	return a.ops.ListNotifications(a.operationContext(ctx), userID, options)
}
func (a *Client) GetNotification(ctx context.Context, userID, id string) (notify.Item, error) {
	return a.ops.GetNotification(a.operationContext(ctx), userID, id)
}
func (a *Client) SetNotificationRead(ctx context.Context, userID, id string, read bool) (notify.Item, error) {
	return a.ops.SetNotificationRead(a.operationContext(ctx), userID, id, read)
}
func (a *Client) SetNotificationDismissed(ctx context.Context, userID, id string, dismissed bool) (notify.Item, error) {
	return a.ops.SetNotificationDismissed(a.operationContext(ctx), userID, id, dismissed)
}

// MigrateNotifications explicitly prepares the optional inbox tables, even when
// Database.SkipMigrations is true. Scope mappings preserve existing receipts in
// place; they are deployment identity, not an instruction to merge account data.
func MigrateNotifications(ctx context.Context, pool *pgxpool.Pool, cfg Config) error {
	if cfg.Notifications == nil {
		return nil
	}
	n := *cfg.Notifications
	n.Producers = append([]NotificationProducer(nil), n.Producers...)
	for i := range n.Producers {
		if n.Producers[i].TenantID.IsZero() {
			n.Producers[i].TenantID = cfg.DefaultTenantID
		}
	}
	return engine.MigrateNotifications(ctx, pool, cfg.Database, &n, cfg.DefaultTenantID)
}

// NotificationAdoption maps exact legacy receipt origins to one current issue.
// It is maintenance data, not a runtime alias or wildcard deletion interface.
type NotificationAdoption = notify.Adoption

// AdoptNotifications runs a bounded explicit cutover batch while old writers
// are stopped. A current-identity receipt wins; otherwise the newest matching
// legacy receipt wins (created_at, ID descending). Its ID/read/archive survive;
// redundant legacy receipts remain hidden. Producer state never moves backwards.
func (a *Client) AdoptNotifications(ctx context.Context, producer string, batch []notify.Adoption) error {
	return a.engine.AdoptNotifications(a.operationContext(ctx), producer, batch)
}
