package engine

// SCIM provisioning (Config.Provisioning). The users triggers (migration
// 0010) record a provisioning_changes row per target in every transaction
// that changes what a SCIM User shows. Every Interval a River job per target
// sends its pending users' current state in bulk requests and deletes the
// rows the target accepted; a refused user is retried with backoff, an
// unreachable target as a whole. A new target first queues every account,
// and a periodic reconciliation lists the target's users and queues what
// drifted.

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/riverqueue/river"
	"github.com/riverqueue/river/rivertype"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/clientcredentials"

	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/internal/config"
	"github.com/open-rails/authkit/internal/db"
	"github.com/open-rails/authkit/internal/scim"
)

const (
	// provisioningRunBudget bounds one run's sending; the next run goes on.
	provisioningRunBudget = 4 * time.Minute
	// provisioningMaxBackoff caps a retry's wait (or Interval, when longer).
	provisioningMaxBackoff = time.Hour
	// provisioningWindow is how many outbox rows one batch reads.
	provisioningWindow = 1000
	// provisioningSyncPage is how many accounts the initial sync queues per
	// transaction.
	provisioningSyncPage = 5000
	// provisioningRequestTimeout bounds one call to a target.
	provisioningRequestTimeout = time.Minute
	// inProcessBase is the base URL of a Handler target's requests.
	inProcessBase = "http://scim.in-process"
)

// provisioningTarget is a configured target and its client.
type provisioningTarget struct {
	name   string
	client *scim.Client
}

// initProvisioning builds the targets' clients and registers them, so the
// users triggers record changes for them from now on.
func (s *Engine) initProvisioning(ctx context.Context) error {
	if s.pg == nil {
		return nil
	}
	for _, t := range s.cfg.Provisioning.Targets {
		s.provisioning = append(s.provisioning, &provisioningTarget{name: t.Name, client: provisioningClient(t)})
		if err := s.q.ProvisioningTargetRegister(ctx, db.ProvisioningTargetRegisterParams{Issuer: s.cfg.Token.Issuer, Name: t.Name}); err != nil {
			return fmt.Errorf("authkit: register provisioning target %s: %w", t.Name, err)
		}
	}
	return nil
}

// pruneProvisioningTargets forgets this issuer's targets no longer
// configured, with their pending changes. Only Start runs it: a client
// built for something else never forgets a target.
func (s *Engine) pruneProvisioningTargets(ctx context.Context) error {
	names := make([]string, 0, len(s.provisioning))
	for _, t := range s.provisioning {
		names = append(names, t.name)
	}
	pruned, err := s.q.ProvisioningTargetsPrune(ctx, db.ProvisioningTargetsPruneParams{Issuer: s.cfg.Token.Issuer, Names: names})
	for _, name := range pruned {
		slog.InfoContext(ctx, "authkit: provisioning target no longer configured; forgotten with its pending changes", "target", name)
	}
	return err
}

func (s *Engine) provisioningTarget(name string) *provisioningTarget {
	for _, t := range s.provisioning {
		if t.name == name {
			return t
		}
	}
	return nil
}

// provisioningClient calls t over HTTP, or its Handler in process, with its
// credential.
func provisioningClient(t config.ProvisioningTarget) *scim.Client {
	base, transport := t.URL, http.DefaultTransport.(*http.Transport).Clone()
	var rt http.RoundTripper = transport
	if t.Handler != nil {
		base, rt = inProcessBase, handlerTransport{t.Handler}
	}
	switch {
	case t.BearerToken != "":
		rt = bearerTransport{token: t.BearerToken, base: rt}
	case t.ClientCredentials != nil:
		cc := t.ClientCredentials
		creds := clientcredentials.Config{ClientID: cc.ClientID, ClientSecret: cc.ClientSecret, TokenURL: cc.TokenURL, Scopes: cc.Scopes}
		if cc.Resource != "" {
			creds.EndpointParams = url.Values{"resource": {cc.Resource}}
		}
		tokenHTTP := &http.Client{Timeout: provisioningRequestTimeout, Transport: http.DefaultTransport.(*http.Transport).Clone()}
		rt = &oauth2.Transport{Source: creds.TokenSource(context.WithValue(context.Background(), oauth2.HTTPClient, tokenHTTP)), Base: rt}
	}
	return &scim.Client{Base: base, HTTP: &http.Client{Transport: rt, Timeout: provisioningRequestTimeout}}
}

type bearerTransport struct {
	token string
	base  http.RoundTripper
}

func (b bearerTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	r = r.Clone(r.Context())
	r.Header.Set("Authorization", "Bearer "+b.token)
	return b.base.RoundTrip(r)
}

// handlerTransport serves a request with an in-process handler.
type handlerTransport struct{ h http.Handler }

func (t handlerTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	r = r.Clone(r.Context())
	r.RequestURI = r.URL.RequestURI()
	r.RemoteAddr = "127.0.0.1:0"
	if r.Body == nil {
		r.Body = http.NoBody // as a server's request always has one
	}
	w := &responseRecorder{header: http.Header{}}
	t.h.ServeHTTP(w, r)
	if w.status == 0 {
		w.status = http.StatusOK
	}
	return &http.Response{
		Status: fmt.Sprintf("%d %s", w.status, http.StatusText(w.status)), StatusCode: w.status,
		Proto: "HTTP/1.1", ProtoMajor: 1, ProtoMinor: 1, Header: w.header,
		Body: io.NopCloser(bytes.NewReader(w.body.Bytes())), ContentLength: int64(w.body.Len()), Request: r,
	}, nil
}

type responseRecorder struct {
	header http.Header
	status int
	body   bytes.Buffer
}

func (w *responseRecorder) Header() http.Header { return w.header }

func (w *responseRecorder) WriteHeader(status int) {
	if w.status == 0 {
		w.status = status
	}
}

func (w *responseRecorder) Write(b []byte) (int, error) {
	w.WriteHeader(http.StatusOK)
	return w.body.Write(b)
}

// provisioningBackoff is the wait after failures: Interval, doubling, up to
// an hour (or Interval when longer).
func (s *Engine) provisioningBackoff(failures int) time.Duration {
	interval := s.cfg.Provisioning.Interval
	ceiling := max(interval, provisioningMaxBackoff)
	return min(interval<<min(max(failures-1, 0), 20), ceiling)
}

type provisioningArgs struct {
	Schema string `json:"schema"`
	Issuer string `json:"issuer"`
	Target string `json:"target"`
}

func (provisioningArgs) Kind() string { return "authkit_provisioning" }

func provisioningQueue(schema, issuer string) string {
	digest := sha256.Sum256([]byte(schema + "\x00" + issuer))
	return "authkit_provisioning-" + hex.EncodeToString(digest[:20])
}

// registerProvisioning adds the worker, its queue and one periodic job per
// target. A target has at most one job waiting or running.
func (s *Engine) registerProvisioning(cfg *river.Config) error {
	if err := river.AddWorkerSafely(cfg.Workers, &provisioningWorker{engine: s}); err != nil {
		return err
	}
	if len(s.cfg.Provisioning.Targets) == 0 {
		return nil
	}
	queue := provisioningQueue(s.dbSchema(), s.cfg.Token.Issuer)
	if existing, ok := cfg.Queues[queue]; ok && existing.MaxWorkers < 1 {
		return fmt.Errorf("authkit: provisioning queue %q requires workers", queue)
	}
	if _, ok := cfg.Queues[queue]; !ok {
		cfg.Queues[queue] = river.QueueConfig{MaxWorkers: len(s.cfg.Provisioning.Targets)}
	}
	unique := river.UniqueOpts{ByArgs: true, ByState: []rivertype.JobState{
		rivertype.JobStateAvailable, rivertype.JobStatePending, rivertype.JobStateRunning,
		rivertype.JobStateRetryable, rivertype.JobStateScheduled,
	}}
	for _, t := range s.cfg.Provisioning.Targets {
		args := provisioningArgs{Schema: s.dbSchema(), Issuer: s.cfg.Token.Issuer, Target: t.Name}
		digest := sha256.Sum256([]byte(args.Schema + "\x00" + args.Issuer + "\x00" + args.Target))
		cfg.PeriodicJobs = append(cfg.PeriodicJobs, river.NewPeriodicJob(
			river.PeriodicInterval(s.cfg.Provisioning.Interval),
			func() (river.JobArgs, *river.InsertOpts) {
				return args, &river.InsertOpts{Queue: queue, UniqueOpts: unique}
			}, &river.PeriodicJobOpts{ID: "authkit_provisioning_" + hex.EncodeToString(digest[:16]), RunOnStart: true},
		))
	}
	return nil
}

type provisioningWorker struct {
	river.WorkerDefaults[provisioningArgs]
	engine *Engine
}

func (w *provisioningWorker) Timeout(*river.Job[provisioningArgs]) time.Duration {
	return provisioningRunBudget + 2*provisioningRequestTimeout
}

func (w *provisioningWorker) Work(ctx context.Context, job *river.Job[provisioningArgs]) error {
	s := w.engine
	if job.Args.Schema != s.dbSchema() || job.Args.Issuer != s.cfg.Token.Issuer {
		return river.JobCancel(errors.New("authkit: provisioning job routed to a different application"))
	}
	t := s.provisioningTarget(job.Args.Target)
	if t == nil {
		return nil // configured on another build of this issuer
	}
	return s.runProvisioning(ctx, t)
}

// runProvisioning is one run for t: the initial sync's queueing, every due
// change in bulk until none is left or the budget is spent, then a
// reconciliation when one is due. A failure to reach the target is recorded
// on it, and only a database error fails the job.
func (s *Engine) runProvisioning(ctx context.Context, t *provisioningTarget) error {
	key := db.ProvisioningTargetParams{Issuer: s.cfg.Token.Issuer, Name: t.name}
	row, err := s.q.ProvisioningTarget(ctx, key)
	if errors.Is(err, pgx.ErrNoRows) {
		// Pruned by a replica running an older configuration.
		if err := s.q.ProvisioningTargetRegister(ctx, db.ProvisioningTargetRegisterParams(key)); err != nil {
			return err
		}
		row, err = s.q.ProvisioningTarget(ctx, key)
	}
	if err != nil {
		return err
	}
	start := s.nowTime()
	if row.RetryAt != nil && start.Before(*row.RetryAt) {
		return nil
	}
	if row.SyncedAt == nil {
		if err := s.queueInitialSync(ctx, t, row.SyncAfter); err != nil {
			return err
		}
		row.ReconciledAt = &start
	}
	spc, err := t.client.ServiceProviderConfig(ctx)
	if scim.IsStatus(err, http.StatusNotFound) {
		spc, err = scim.ServiceProviderConfig{}, nil // no discovery: no bulk
	}
	if err != nil {
		return s.provisioningFailed(ctx, t, row, err)
	}
	run := &provisioningRun{engine: s, target: t, spc: spc, deadline: start.Add(provisioningRunBudget), rounds: map[string]int{}}
	caughtUp, err := run.deliver(ctx)
	var unreachable *targetError
	if errors.As(err, &unreachable) {
		return s.provisioningFailed(ctx, t, row, unreachable.err)
	}
	if err != nil {
		return err
	}
	interval := s.cfg.Provisioning.ReconcileInterval
	if caughtUp && interval > 0 && (row.ReconciledAt == nil || s.nowTime().Sub(*row.ReconciledAt) >= interval) {
		err := run.reconcile(ctx)
		if errors.As(err, &unreachable) {
			return s.provisioningFailed(ctx, t, row, unreachable.err)
		}
		if err != nil {
			return err
		}
	}
	return s.q.ProvisioningTargetRan(ctx, db.ProvisioningTargetRanParams{
		Issuer: s.cfg.Token.Issuer, Name: t.name, Clean: run.lastError == "", LastError: nullable(run.lastError),
	})
}

// provisioningFailed records that t could not be reached or refused a whole
// request; the next run waits out the backoff.
func (s *Engine) provisioningFailed(ctx context.Context, t *provisioningTarget, row db.ProvisioningTarget, cause error) error {
	retry := s.nowTime().Add(s.provisioningBackoff(int(row.Failures) + 1))
	slog.WarnContext(ctx, "authkit: provisioning target unavailable; will retry", "target", t.name, "attempt", row.Failures+1, "retry_at", retry, "error", cause)
	msg := cause.Error()
	return s.q.ProvisioningTargetFailed(ctx, db.ProvisioningTargetFailedParams{
		Issuer: s.cfg.Token.Issuer, Name: t.name, RetryAt: &retry, LastError: &msg,
	})
}

// queueInitialSync queues every account for a new target, a page per
// transaction, resuming after the last page a previous run queued.
func (s *Engine) queueInitialSync(ctx context.Context, t *provisioningTarget, after *string) error {
	issuer := s.cfg.Token.Issuer
	for {
		done := false
		err := pgx.BeginFunc(ctx, s.pg, func(tx pgx.Tx) error {
			q := s.qtx(tx)
			ids, err := q.ProvisioningSyncPage(ctx, db.ProvisioningSyncPageParams{Issuer: issuer, Target: t.name, After: after, PageSize: provisioningSyncPage})
			if err != nil {
				return err
			}
			if len(ids) < provisioningSyncPage {
				done = true
				return q.ProvisioningSyncDone(ctx, db.ProvisioningSyncDoneParams{Issuer: issuer, Name: t.name})
			}
			last := ids[0]
			for _, id := range ids {
				last = max(last, id) // canonical lowercase uuids sort as their bytes
			}
			after = &last
			return q.ProvisioningSyncAdvance(ctx, db.ProvisioningSyncAdvanceParams{Issuer: issuer, Name: t.name, After: last})
		})
		if err != nil || done {
			return err
		}
	}
}

// ProvisioningTargets reports each configured target's delivery.
func (s *Engine) ProvisioningTargets(ctx context.Context) ([]iam.ProvisioningTarget, error) {
	out := []iam.ProvisioningTarget{}
	if len(s.provisioning) == 0 {
		return out, nil
	}
	names := make([]string, 0, len(s.provisioning))
	for _, t := range s.provisioning {
		names = append(names, t.name)
	}
	rows, err := s.q.ProvisioningTargetStatuses(ctx, db.ProvisioningTargetStatusesParams{Issuer: s.cfg.Token.Issuer, Names: names})
	if err != nil {
		return nil, err
	}
	for _, r := range rows {
		out = append(out, iam.ProvisioningTarget{
			Name: r.Name, SyncedAt: r.SyncedAt, ReconciledAt: r.ReconciledAt, LastSuccessAt: r.LastSuccessAt,
			FailingSince: r.FailingSince, LastError: r.LastError, Backlog: int(r.Backlog),
		})
	}
	return out, nil
}

// scimUser is u as a SCIM User at asOf, externalId its id: its contact
// (accountContact), userName its username or else its id, and whether it is
// usable.
func scimUser(u db.User, asOf time.Time) scim.User {
	active := u.DeletedAt == nil && !banInForce(u.BannedAt, u.BannedUntil, asOf)
	c := accountContact(u)
	out := scim.User{Schemas: []string{scim.SchemaUser}, ExternalID: u.ID, UserName: c.Username, Active: &active}
	if out.UserName == "" {
		out.UserName = u.ID
	}
	if c.Name != "" {
		out.Name, out.DisplayName = &scim.Name{Formatted: c.Name}, c.Name
	}
	if c.Email != "" {
		out.Emails = []scim.Email{{Value: c.Email, Primary: true}}
	}
	return out
}
