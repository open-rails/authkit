package authkit

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/open-rails/authkit/internal/config"
	"github.com/open-rails/authkit/internal/engine"
	"github.com/open-rails/authkit/notify"
	riverhelpers "github.com/open-rails/helpers/river"
	"github.com/riverqueue/river"
	"github.com/riverqueue/river/riverdriver/riverpgxv5"
)

// RemoteNotificationConfig is one trusted AuthKit publication destination.
// BaseURL includes AuthKit's versioned API base. Producer is the declared remote
// binding name. Credentials are resolved at each attempt and never enter jobs.
type RemoteNotificationConfig struct {
	BaseURL    string
	Producer   string
	Token      func(context.Context) (string, error)
	HTTPClient *http.Client
}

// NotificationDelivery supplies one source-database worker for all configured
// remote inbox destinations. It owns no pool or background goroutine. Compose
// RiverJobs into the host fleet before accepting publications or withdrawals.
type NotificationDelivery struct {
	pool     *pgxpool.Pool
	schema   string
	targets  map[string]*remoteNotificationPublisher
	producer *river.Client[pgx.Tx]
}

type remoteNotificationPublisher struct {
	delivery *NotificationDelivery
	name     string
	endpoint string
	token    func(context.Context) (string, error)
	http     *http.Client
}

// NewNotificationDelivery binds a source database's River queue to trusted
// destinations. The host migrates River and starts/stops its ordinary fleet.
func NewNotificationDelivery(pool *pgxpool.Pool, riverSchema string, destinations map[string]RemoteNotificationConfig) (*NotificationDelivery, error) {
	if pool == nil || riverSchema == "" || len(destinations) == 0 {
		return nil, errors.New("authkit: notification delivery needs source pool, River schema and destinations")
	}
	client, err := river.NewClient(riverpgxv5.New(pool), &river.Config{Schema: riverSchema})
	if err != nil {
		return nil, err
	}
	d := &NotificationDelivery{pool: pool, schema: riverSchema, producer: client, targets: map[string]*remoteNotificationPublisher{}}
	for name, c := range destinations {
		u, err := url.Parse(strings.TrimRight(c.BaseURL, "/"))
		if err != nil || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || (u.Scheme != "https" && u.Scheme != "http") || name == "" || !config.ValidNotificationProducerName(c.Producer) || c.Token == nil {
			return nil, fmt.Errorf("authkit: invalid notification destination %q", name)
		}
		h := http.Client{Timeout: 15 * time.Second}
		if c.HTTPClient != nil {
			h = *c.HTTPClient
		}
		if h.Timeout <= 0 {
			h.Timeout = 15 * time.Second
		}
		h.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
		d.targets[name] = &remoteNotificationPublisher{delivery: d, name: name, endpoint: u.String() + "/notifications/" + url.PathEscape(c.Producer), token: c.Token, http: &h}
	}
	return d, nil
}

func (d *NotificationDelivery) Publisher(name string) (notify.Publisher, error) {
	if d == nil {
		return nil, errors.New("authkit: notification delivery is nil")
	}
	p, ok := d.targets[name]
	if !ok {
		return nil, fmt.Errorf("authkit: unknown notification destination %q", name)
	}
	return p, nil
}

const NotificationDeliveryQueue = "authkit_notifications"

type notificationDeliveryArgs struct {
	Destination string            `json:"destination"`
	Mutations   []notify.Mutation `json:"mutations"`
}

func (notificationDeliveryArgs) Kind() string { return "authkit_notification_delivery" }

func (d *NotificationDelivery) RiverJobs() riverhelpers.Contribution {
	return riverhelpers.NewContribution("authkit-notification-delivery", func(_ context.Context, cfg *river.Config) error {
		if cfg.Schema != d.schema {
			return errors.New("authkit: notification delivery River schema mismatch")
		}
		if q, ok := cfg.Queues[NotificationDeliveryQueue]; ok && q.MaxWorkers < 1 {
			return errors.New("authkit: notification delivery queue requires workers")
		} else if !ok {
			cfg.Queues[NotificationDeliveryQueue] = river.QueueConfig{MaxWorkers: 2}
		}
		return river.AddWorkerSafely(cfg.Workers, &notificationDeliveryWorker{delivery: d})
	}, func(ctx context.Context, b riverhelpers.Binding) error {
		// A transactional producer and its worker must observe the same committed
		// jobs. Compare the actual database identity, never a connection string.
		return checkNotificationDeliveryDatabase(ctx, d.pool, b.Pool)
	}, func() error { return nil })
}

func checkNotificationDeliveryDatabase(ctx context.Context, source, worker *pgxpool.Pool) error {
	return engine.CheckNotificationDeliveryDatabase(ctx, source, worker)
}

const notificationRequestLimit = 8 << 20

func encodeNotificationBatch(changes []notify.Mutation) ([]byte, error) {
	if len(changes) > notify.MaxMutations {
		return nil, fmt.Errorf("%w: too many notification mutations", notify.ErrInvalid)
	}
	var body bytes.Buffer
	encoder := json.NewEncoder(&body)
	// RawMessage can contain HTML; default escaping can expand an otherwise
	// valid 6.4 MiB batch beyond the receiver's dedicated 8 MiB bound.
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(struct {
		Mutations []notify.Mutation `json:"mutations"`
	}{changes}); err != nil {
		return nil, err
	}
	if body.Len() > notificationRequestLimit {
		return nil, fmt.Errorf("%w: notification batch exceeds request bound", notify.ErrInvalid)
	}
	return body.Bytes(), nil
}

// deliver is worker-only. Public producer operations always commit a source
// delivery obligation, including when the caller omits an explicit transaction.
func (p *remoteNotificationPublisher) deliver(ctx context.Context, changes []notify.Mutation) error {
	data, err := encodeNotificationBatch(changes)
	if err != nil {
		return err
	}
	if len(changes) == 0 {
		return nil
	}
	token, err := p.token(ctx)
	if err != nil {
		return err
	}
	if strings.TrimSpace(token) == "" {
		return errors.New("authkit: notification publisher credential unavailable")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, p.endpoint, bytes.NewReader(data))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	res, err := p.http.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(res.Body, 64<<10))
	if res.StatusCode != http.StatusNoContent {
		return fmt.Errorf("authkit: notification destination returned HTTP %d", res.StatusCode)
	}
	return nil
}

var _ notify.Publisher = (*remoteNotificationPublisher)(nil)

func (p *remoteNotificationPublisher) Publish(ctx context.Context, batch []notify.Publication, tx ...pgx.Tx) error {
	changes, err := notificationPublications(batch)
	if err != nil {
		return err
	}
	return p.accept(ctx, changes, tx)
}

func (p *remoteNotificationPublisher) Withdraw(ctx context.Context, batch []notify.Withdrawal, tx ...pgx.Tx) error {
	changes, err := notificationWithdrawals(batch)
	if err != nil {
		return err
	}
	return p.accept(ctx, changes, tx)
}

func (p *remoteNotificationPublisher) accept(ctx context.Context, changes []notify.Mutation, transactions []pgx.Tx) error {
	if err := notificationTransaction(transactions); err != nil {
		return err
	}
	if _, err := encodeNotificationBatch(changes); err != nil {
		return err
	}
	if len(changes) == 0 {
		return nil
	}
	if len(transactions) == 0 {
		return pgx.BeginFunc(ctx, p.delivery.pool, func(tx pgx.Tx) error { return p.enqueue(ctx, tx, changes) })
	}
	return p.enqueue(ctx, transactions[0], changes)
}

func (p *remoteNotificationPublisher) enqueue(ctx context.Context, tx pgx.Tx, changes []notify.Mutation) error {
	if err := engine.CheckNotificationTransactionDatabase(ctx, tx, p.delivery.pool); err != nil {
		return err
	}
	return pgx.BeginFunc(ctx, tx, func(batch pgx.Tx) error {
		_, err := p.delivery.producer.InsertTx(ctx, batch, notificationDeliveryArgs{Destination: p.name, Mutations: changes}, &river.InsertOpts{Queue: NotificationDeliveryQueue, MaxAttempts: 100})
		return err
	})
}

type notificationDeliveryWorker struct {
	river.WorkerDefaults[notificationDeliveryArgs]
	delivery *NotificationDelivery
}

func (*notificationDeliveryWorker) Timeout(*river.Job[notificationDeliveryArgs]) time.Duration {
	return time.Minute
}
func (w *notificationDeliveryWorker) Work(ctx context.Context, job *river.Job[notificationDeliveryArgs]) error {
	p, ok := w.delivery.targets[job.Args.Destination]
	if !ok {
		return fmt.Errorf("authkit: notification destination %q is not configured", job.Args.Destination)
	}
	return p.deliver(ctx, job.Args.Mutations)
}
