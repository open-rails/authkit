package authkit

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/internal/engine"
	"github.com/open-rails/authkit/notify"
)

// Notifications registers producer in this Client's tenant and returns its
// publisher: the account inbox's one way in, for AuthKit's host and the
// engines it embeds (ContentKit, OpenRails), each registering its own.
// Registering the same producer again returns its publisher; another under
// its name is refused. Remote publication (POST {api}/notifications/{name})
// needs the producer registered, with its permission, on the replica
// serving it. The publisher's transaction method must use the account
// database; it never opens another transaction behind the caller.
func (a *Client) Notifications(producer NotificationProducer) (notify.Publisher, error) {
	if a == nil || a.engine == nil {
		return nil, errors.New("authkit: notification publisher needs a client")
	}
	ctx := a.operationContext(context.Background())
	if err := a.engine.RegisterNotificationProducer(ctx, producer); err != nil {
		return nil, err
	}
	return &accountNotificationPublisher{engine: a.engine, tenant: a.TenantID(), producer: producer.Name}, nil
}

type accountNotificationPublisher struct {
	engine   *engine.Engine
	tenant   iam.TenantID
	producer string
}

var _ notify.Publisher = (*accountNotificationPublisher)(nil)

func (p *accountNotificationPublisher) Publish(ctx context.Context, batch []notify.Publication, tx ...pgx.Tx) error {
	changes, err := notificationPublications(batch)
	if err != nil {
		return err
	}
	return p.accept(ctx, changes, tx)
}
func (p *accountNotificationPublisher) Withdraw(ctx context.Context, batch []notify.Withdrawal, tx ...pgx.Tx) error {
	changes, err := notificationWithdrawals(batch)
	if err != nil {
		return err
	}
	return p.accept(ctx, changes, tx)
}
func (p *accountNotificationPublisher) accept(ctx context.Context, changes []notify.Mutation, transactions []pgx.Tx) error {
	if err := notificationTransaction(transactions); err != nil {
		return err
	}
	ctx = engine.WithTenant(ctx, p.tenant)
	if len(transactions) == 0 {
		return p.engine.ApplyNotifications(ctx, p.producer, changes)
	}
	return p.engine.ApplyNotificationsTx(ctx, transactions[0], p.producer, changes)
}

func notificationTransaction(transactions []pgx.Tx) error {
	if len(transactions) > 1 || len(transactions) == 1 && transactions[0] == nil {
		return fmt.Errorf("%w: omit transaction or provide exactly one non-nil transaction", notify.ErrInvalid)
	}
	return nil
}

func notificationPublications(batch []notify.Publication) ([]notify.Mutation, error) {
	if len(batch) > notify.MaxMutations {
		return nil, fmt.Errorf("%w: too many notification publications", notify.ErrInvalid)
	}
	changes := make([]notify.Mutation, len(batch))
	for i, publication := range batch {
		p, err := notify.ValidatePublication(publication)
		if err != nil {
			return nil, err
		}
		changes[i] = notify.Mutation{Input: notify.Input{Recipient: notify.Recipient{Audience: notify.AudienceUser, ID: p.RecipientID}, Origin: notify.Origin{ID: p.ID}, Kind: p.Kind, Data: p.Data, CreatedAt: p.CreatedAt, ActionRequested: p.ActionRequested, Severity: p.Severity}, Revision: p.Revision}
	}
	return changes, nil
}

func notificationWithdrawals(batch []notify.Withdrawal) ([]notify.Mutation, error) {
	if len(batch) > notify.MaxMutations {
		return nil, fmt.Errorf("%w: too many notification withdrawals", notify.ErrInvalid)
	}
	changes := make([]notify.Mutation, len(batch))
	for i, withdrawal := range batch {
		if err := notify.ValidateWithdrawal(withdrawal); err != nil {
			return nil, err
		}
		changes[i] = notify.Mutation{Input: notify.Input{Recipient: notify.Recipient{Audience: notify.AudienceUser, ID: withdrawal.RecipientID}, Origin: notify.Origin{ID: withdrawal.ID}}, Revision: withdrawal.Revision, Withdrawn: true}
	}
	return changes, nil
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
