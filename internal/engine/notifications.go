package engine

import (
	"context"
	"fmt"
	"slices"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/open-rails/authkit/auth"
	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/internal/config"
	"github.com/open-rails/authkit/internal/db"
	"github.com/open-rails/authkit/internal/ident"
	"github.com/open-rails/authkit/notify"
	notifypg "github.com/open-rails/authkit/notify/postgres"
)

// notificationProducer is a registered producer, bound to its tenant and,
// with app visibility, to this deployment's app (its issuer).
type notificationProducer struct {
	config.NotificationProducer
	TenantID iam.TenantID
	AppID    string
}

// migrateNotifications installs the account inbox in AuthKit's schema.
func migrateNotifications(ctx context.Context, pool *pgxpool.Pool, schema string) error {
	return notifypg.Migrate(ctx, pool, schema)
}

// NotificationScope is the tenant's inbox namespace: authkit:<tenant ID>.
func (s *Engine) NotificationScope(ctx context.Context) (string, error) {
	tenant, err := s.tenantID(ctx)
	if err != nil {
		return "", err
	}
	return "authkit:" + tenant.String(), nil
}

// notificationStore is the tenant's inbox; a view shows tenant-wide
// notifications and this deployment's app's.
func (s *Engine) notificationStore(ctx context.Context, view bool) (*notifypg.Store, error) {
	scope, err := s.NotificationScope(ctx)
	if err != nil {
		return nil, err
	}
	c := notifypg.Config{Schema: s.schema, Scope: scope}
	if view {
		c.AppView = &notify.AppView{AppID: s.cfg.Issuer}
	}
	return notifypg.New(s.pg, c)
}

// RegisterNotificationProducer registers p in the selected tenant, binding
// its notifications to this deployment's app when they are app-visible.
// Registering the same producer again is a no-op; another under its name is
// refused.
func (s *Engine) RegisterNotificationProducer(ctx context.Context, p config.NotificationProducer) error {
	p, err := config.NormalizeNotificationProducer(p)
	if err != nil {
		return err
	}
	tenant, err := s.tenantID(ctx)
	if err != nil {
		return err
	}
	r := notificationProducer{NotificationProducer: p, TenantID: tenant}
	if p.Visibility == notify.VisibilityApp {
		r.AppID = s.cfg.Issuer
	}
	key := tenant.String() + ":" + p.Name
	s.producersMu.Lock()
	defer s.producersMu.Unlock()
	if have, ok := s.producers[key]; ok {
		if have != r {
			return fmt.Errorf("authkit notifications: producer %q is registered with another binding", p.Name)
		}
		return nil
	}
	if s.producers == nil {
		s.producers = map[string]notificationProducer{}
	}
	s.producers[key] = r
	return nil
}

// notificationProducer resolves one registered, immutable binding for the
// selected tenant. Native callers hold a host capability; HTTP also
// authorizes it.
func (s *Engine) notificationProducer(ctx context.Context, name string) (notificationProducer, error) {
	tenant, err := s.tenantID(ctx)
	if err != nil {
		return notificationProducer{}, err
	}
	s.producersMu.Lock()
	p, ok := s.producers[tenant.String()+":"+name]
	s.producersMu.Unlock()
	if !ok {
		return notificationProducer{}, fmt.Errorf("%w: notification producer", auth.ErrForbidden)
	}
	return p, nil
}

// AuthorizeNotifications rechecks the actor's current authority in exactly the
// producer's configured group. Source metadata is never an authorization claim.
func (s *Engine) AuthorizeNotifications(ctx context.Context, who auth.Identity, name string) error {
	p, err := s.notificationProducer(ctx, name)
	if err != nil {
		return err
	}
	if p.PermissionGroupID == "" || p.Permission == "" {
		return auth.ErrForbidden
	}
	group, err := s.Group(ctx, iam.GroupByID(p.PermissionGroupID))
	if err != nil {
		return err
	}
	if group.TenantID != p.TenantID || group.Persona != ident.Perm(p.Permission).Persona() {
		return auth.ErrForbidden
	}
	allowed, err := s.CanDirect(ctx, who, iam.GroupByID(p.PermissionGroupID), ident.Perm(p.Permission))
	if err != nil {
		return err
	}
	if !allowed {
		return auth.ErrForbidden
	}
	return nil
}

func (s *Engine) ApplyNotifications(ctx context.Context, name string, changes []notify.Mutation) error {
	if err := s.requirePG(); err != nil {
		return err
	}
	return pgx.BeginFunc(ctx, s.pg, func(tx pgx.Tx) error { return s.ApplyNotificationsTx(ctx, tx, name, changes) })
}

func bindNotifications(p notificationProducer, changes []notify.Mutation) ([]notify.Mutation, error) {
	if len(changes) > notify.MaxMutations {
		return nil, fmt.Errorf("%w: too many notification mutations", notify.ErrInvalid)
	}
	batch := slices.Clone(changes)
	for i := range batch {
		m := &batch[i]
		if id, ok := canonicalUUID(m.Recipient.ID); !ok || id != m.Recipient.ID {
			return nil, fmt.Errorf("%w: canonical account ID required", notify.ErrInvalid)
		}
		if m.Recipient.Audience != notify.AudienceUser || m.Origin.System != "" && m.Origin.System != p.Origin.System || m.Origin.Scope != "" && m.Origin.Scope != p.Origin.Scope || m.Visibility != "" && m.Visibility != p.Visibility || m.AppID != "" && m.AppID != p.AppID {
			return nil, auth.ErrForbidden
		}
		m.Origin.System, m.Origin.Scope = p.Origin.System, p.Origin.Scope
		m.Visibility, m.AppID = p.Visibility, p.AppID
		var err error
		*m, err = notify.ValidateMutation(*m)
		if err != nil {
			return nil, err
		}
	}
	return batch, nil
}

// ApplyNotificationsTx validates recipient ownership inside the source
// transaction and joins the durable inbox write. Account erasure and delayed
// publication serialize through the inbox recipient guard.
func (s *Engine) ApplyNotificationsTx(ctx context.Context, host pgx.Tx, name string, changes []notify.Mutation) error {
	p, err := s.notificationProducer(ctx, name)
	if err != nil {
		return err
	}
	batch, err := bindNotifications(p, changes)
	if err != nil {
		return err
	}
	if len(batch) == 0 {
		return nil
	}
	if host == nil {
		return fmt.Errorf("%w: notification transaction required", notify.ErrInvalid)
	}
	store, err := s.notificationStore(ctx, false)
	if err != nil {
		return err
	}
	tx, err := s.joinHostTransaction(ctx, host)
	if err != nil {
		return err
	}
	defer tx.Rollback(context.WithoutCancel(ctx))
	ids := make([]string, 0, len(batch))
	for _, m := range batch {
		ids = append(ids, m.Recipient.ID)
	}
	accounts, err := s.qtx(tx).TenantUsersByIDs(ctx, db.TenantUsersByIDsParams{TenantID: s.tenantKey(ctx), Ids: ids})
	if err != nil {
		return err
	}
	live := make(map[string]bool, len(accounts))
	for _, account := range accounts {
		live[account.ID] = account.DeletedAt == nil
	}
	// Missing accounts are terminal. A recoverably deleted account still
	// accepts withdrawals so restoring it cannot resurrect obsolete notices.
	batch = slices.DeleteFunc(batch, func(m notify.Mutation) bool {
		active, exists := live[m.Recipient.ID]
		return !exists || !active && !m.Withdrawn
	})

	// Existing account/app fences are terminal even if an older restore has
	// left an account row. Serialize their publication checks through the store.
	scope, _ := s.NotificationScope(ctx)
	recipients := pgx.Identifier{s.schema, "notify_recipients"}.Sanitize()
	appFences := pgx.Identifier{s.schema, "notify_app_erasures"}.Sanitize()
	// Match the generic recipient guard lock order before inspecting legacy
	// app fences. A concurrent erasure cannot slip between the filter and write.
	ids = ids[:0]
	for _, m := range batch {
		ids = append(ids, m.Recipient.ID)
	}
	slices.Sort(ids)
	ids = slices.Compact(ids)
	if _, err := tx.Exec(ctx, `INSERT INTO `+recipients+`(scope,audience,recipient) SELECT $1,'user',id FROM unnest($2::text[]) id ORDER BY id ON CONFLICT DO NOTHING`, scope, ids); err != nil {
		return err
	}
	guards, err := tx.Query(ctx, `SELECT recipient FROM `+recipients+` WHERE scope=$1 AND audience='user' AND recipient=ANY($2) ORDER BY recipient FOR UPDATE`, scope, ids)
	if err != nil {
		return err
	}
	if _, err = pgx.CollectRows(guards, pgx.RowTo[string]); err != nil {
		return err
	}
	rows, err := tx.Query(ctx, `SELECT recipient FROM `+recipients+` WHERE scope=$1 AND audience='user' AND recipient=ANY($2) AND erased_at IS NOT NULL
 UNION SELECT recipient FROM `+appFences+` WHERE scope=$1 AND audience='user' AND recipient=ANY($2)
AND $3='app' AND ((app_id<>'' AND app_id=$4) OR (source<>'' AND source=$5 AND source_scope=$6))`, scope, ids, p.Visibility, p.AppID, p.Origin.System, p.Origin.Scope)
	if err != nil {
		return err
	}
	erased, err := pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil {
		return err
	}
	batch = slices.DeleteFunc(batch, func(m notify.Mutation) bool { return slices.Contains(erased, m.Recipient.ID) })
	// Erasure may overtake the user snapshot. Inbox guards reject it; retrying
	// the batch then observes the missing account and completes without delivery.
	if err := store.ApplyTx(ctx, tx, batch); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func (s *Engine) ListNotifications(ctx context.Context, userID string, options notify.ListOptions) (notify.Page, error) {
	if err := s.requireTenantUser(ctx, s.q, userID); err != nil {
		return notify.Page{}, err
	}
	store, err := s.notificationStore(ctx, true)
	if err != nil {
		return notify.Page{}, err
	}
	return store.List(ctx, notify.Recipient{Audience: notify.AudienceUser, ID: userID}, options)
}

func (s *Engine) GetNotification(ctx context.Context, userID, id string) (notify.Item, error) {
	if err := s.requireTenantUser(ctx, s.q, userID); err != nil {
		return notify.Item{}, err
	}
	store, err := s.notificationStore(ctx, true)
	if err != nil {
		return notify.Item{}, err
	}
	return store.Get(ctx, notify.Recipient{Audience: notify.AudienceUser, ID: userID}, id)
}

func (s *Engine) SetNotificationRead(ctx context.Context, userID, id string, read bool) (notify.Item, error) {
	if err := s.requireTenantUser(ctx, s.q, userID); err != nil {
		return notify.Item{}, err
	}
	store, err := s.notificationStore(ctx, true)
	if err != nil {
		return notify.Item{}, err
	}
	return store.SetRead(ctx, notify.Recipient{Audience: notify.AudienceUser, ID: userID}, id, read)
}

func (s *Engine) SetNotificationDismissed(ctx context.Context, userID, id string, dismissed bool) (notify.Item, error) {
	if err := s.requireTenantUser(ctx, s.q, userID); err != nil {
		return notify.Item{}, err
	}
	store, err := s.notificationStore(ctx, true)
	if err != nil {
		return notify.Item{}, err
	}
	return store.SetDismissed(ctx, notify.Recipient{Audience: notify.AudienceUser, ID: userID}, id, dismissed)
}

func (s *Engine) eraseNotificationsTx(ctx context.Context, tx pgx.Tx, userID string) error {
	store, err := s.notificationStore(ctx, false)
	if err != nil {
		return err
	}
	return store.EraseRecipientTx(ctx, tx, notify.Recipient{Audience: notify.AudienceUser, ID: userID})
}
