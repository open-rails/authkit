package critical_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/open-rails/authkit"
	"github.com/open-rails/authkit/authtest"
	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/notify"
	notifypg "github.com/open-rails/authkit/notify/postgres"
	riverhelpers "github.com/open-rails/helpers/river"
	"github.com/riverqueue/river"
	"github.com/riverqueue/river/riverdriver/riverpgxv5"
	"github.com/riverqueue/river/rivertype"
)

// notificationApp is the fixture's app: its issuer.
const notificationApp = authtest.Issuer

// This is the already-released source job envelope, intentionally independent
// of the new producer structs. The current worker must still decode it.
type legacyNotificationDeliveryArgs struct {
	Destination string            `json:"destination"`
	Mutations   []notify.Mutation `json:"mutations"`
}

func (legacyNotificationDeliveryArgs) Kind() string { return "authkit_notification_delivery" }

// applicationProducer is the fixture's producer, publishing remotely with
// permission in the tenant's group.
func applicationProducer(tenant iam.TenantID, permission iam.Perm) authkit.NotificationProducer {
	return authkit.NotificationProducer{Name: "application", Origin: notify.OriginScope{System: "application", Scope: "app"},
		PermissionGroupID: tenant.String(), Permission: permission.String()}
}

func notificationFixture(t *testing.T, options ...authtest.Option) (*fixture, notify.Publisher, iam.Role) {
	t.Helper()
	return notificationFixtureWith(t, func(p *authkit.NotificationProducer) {}, options...)
}

// notificationFixtureWith registers the fixture's producer as edit leaves it.
func notificationFixtureWith(t *testing.T, edit func(*authkit.NotificationProducer), options ...authtest.Option) (*fixture, notify.Publisher, iam.Role) {
	t.Helper()
	roles := authkit.NewRoles(authkit.APIKeys, authkit.CustomRoles)
	permission := roles.Tenant.Permission("notifications", "publish")
	role := roles.Tenant.Role("notificationpublisher", permission)
	base := authtest.WithConfig(func(c *authkit.Config) { c.Roles = roles })
	f := newFixture(t, append([]authtest.Option{base}, options...)...)
	producer := applicationProducer(f.tenant, permission)
	edit(&producer)
	sink, err := f.auth.Notifications(producer)
	noError(t, err)
	f.notify = permission
	return f, sink, role
}

func notificationChange(user, id string, revision int64) notify.Mutation {
	return notify.Mutation{Input: notify.Input{Recipient: notify.Recipient{Audience: notify.AudienceUser, ID: user}, Origin: notify.Origin{System: "application", Scope: "app", ID: id}, Kind: "export.ready", Data: json.RawMessage(`{"export_id":"owned"}`), CreatedAt: time.Now().UTC(), Visibility: notify.VisibilityApp, AppID: notificationApp}, Revision: revision}
}

// Existing migration/wire fixtures retain their full legacy envelopes; runtime
// acceptance exercises the narrow public producer interface in one atomic call.
func publishNotificationBatch(ctx context.Context, publisher notify.Publisher, changes []notify.Mutation, tx ...pgx.Tx) error {
	if len(changes) > 0 && changes[0].Withdrawn {
		batch := make([]notify.Withdrawal, len(changes))
		for i, m := range changes {
			if !m.Withdrawn {
				return errors.New("test batch mixes publisher operations")
			}
			batch[i] = notify.Withdrawal{RecipientID: m.Recipient.ID, ID: m.Origin.ID, Revision: m.Revision}
		}
		return publisher.Withdraw(ctx, batch, tx...)
	}
	batch := make([]notify.Publication, len(changes))
	for i, m := range changes {
		if m.Withdrawn {
			return errors.New("test batch mixes publisher operations")
		}
		batch[i] = notify.Publication{RecipientID: m.Recipient.ID, ID: m.Origin.ID, Revision: m.Revision, Kind: m.Kind, Data: m.Data, CreatedAt: m.CreatedAt, ActionRequested: m.ActionRequested || m.Status == notify.StatusOpen, Severity: m.Severity}
	}
	return publisher.Publish(ctx, batch, tx...)
}

func TestCriticalAccountNotifications(t *testing.T) {
	t.Run("AK-J34-C16_legacy_queued_envelopes_preserve_full_content_and_hash_conflicts", func(t *testing.T) {
		f, publisher, role := notificationFixture(t)
		u := f.user(t)
		key, err := f.auth.CreateAPIKey(t.Context(), iam.SystemIdentity(), iam.GroupByID(f.tenant.String()), iam.NewAPIKey{Name: "legacy queue delivery", Role: role})
		noError(t, err)
		delivery, err := authkit.NewNotificationDelivery(f.pool, f.schema, map[string]authkit.RemoteNotificationConfig{"accounts": {BaseURL: f.server.URL + f.auth.APIBase(), Producer: "application", Token: func(context.Context) (string, error) { return key.Secret, nil }}}, nil)
		noError(t, err)
		canonical := notificationChange(u.ID, "legacy:canonical", 1)
		withProvenance := notificationChange(u.ID, "legacy:provenance", 1)
		withProvenance.Origin.Subject = "source-customer"
		withProvenance.Status = notify.StatusOpen
		withProvenance.ActionRequested = true
		producer, err := river.NewClient(riverpgxv5.New(f.pool), &river.Config{Schema: f.schema})
		noError(t, err)
		queued, err := producer.Insert(t.Context(), legacyNotificationDeliveryArgs{Destination: "accounts", Mutations: []notify.Mutation{canonical, withProvenance}}, &river.InsertOpts{Queue: authkit.NotificationDeliveryQueue})
		noError(t, err)
		fleet, err := riverhelpers.New(t.Context(), f.pool, &river.Config{Schema: f.schema}, delivery.RiverJobs())
		noError(t, err)
		noError(t, fleet.Start(context.Background()))
		t.Cleanup(func() {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			noError(t, fleet.Stop(ctx))
		})
		eventually(t, "old serialized job completes through new worker", func() bool {
			job, err := fleet.JobGet(t.Context(), queued.Job.ID)
			noError(t, err)
			return job.State == rivertype.JobStateCompleted
		})
		page, err := f.auth.ListNotifications(t.Context(), u.ID, notify.ListOptions{})
		noError(t, err)
		if len(page.Items) != 2 {
			t.Fatal("old envelope was not delivered intact")
		}
		for _, item := range page.Items {
			_, err = f.auth.SetNotificationRead(t.Context(), u.ID, item.ID, true)
			noError(t, err)
			before, err := f.auth.SetNotificationDismissed(t.Context(), u.ID, item.ID, true)
			noError(t, err)
			if item.Origin.ID == canonical.Origin.ID {
				noError(t, publishNotificationBatch(t.Context(), publisher, []notify.Mutation{canonical}))
			} else {
				if item.Origin.Subject != withProvenance.Origin.Subject || item.Status != notify.StatusOpen {
					t.Fatal("worker discarded legacy provenance or workflow state")
				}
				if err = publishNotificationBatch(t.Context(), publisher, []notify.Mutation{withProvenance}); !errors.Is(err, notify.ErrConflict) {
					t.Fatalf("same-revision semantic change accepted: %v", err)
				}
			}
			after, err := f.auth.GetNotification(t.Context(), u.ID, item.ID)
			noError(t, err)
			if !reflect.DeepEqual(before, after) {
				t.Fatal("same-revision retry or rejected conflict changed the full receipt")
			}
		}
	})
	t.Run("AK-J34-C15_remote_acceptance_never_needs_destination_availability", func(t *testing.T) {
		f, _, _ := notificationFixture(t)
		u := f.user(t)
		var credentials atomic.Int32
		delivery, err := authkit.NewNotificationDelivery(f.pool, f.schema, map[string]authkit.RemoteNotificationConfig{"offline": {
			BaseURL: "http://127.0.0.1:1/auth/v1", Producer: "application",
			Token: func(context.Context) (string, error) {
				credentials.Add(1)
				return "", errors.New("destination credential is offline")
			},
		}}, nil)
		noError(t, err)
		publisher, err := delivery.Publisher("offline")
		noError(t, err)
		publication := notify.Publication{RecipientID: u.ID, ID: "offline:one", Revision: 1, Kind: "export.ready", CreatedAt: time.Now().UTC()}
		noError(t, publisher.Publish(t.Context(), []notify.Publication{publication}))
		noError(t, publisher.Withdraw(t.Context(), []notify.Withdrawal{{RecipientID: u.ID, ID: publication.ID, Revision: 2}}))
		if credentials.Load() != 0 {
			t.Fatal("producer acceptance attempted remote delivery")
		}
		fleet, err := riverhelpers.New(t.Context(), f.pool, &river.Config{Schema: f.schema}, delivery.RiverJobs())
		noError(t, err)
		jobs, err := fleet.JobList(t.Context(), river.NewJobListParams().Kinds("authkit_notification_delivery").First(10))
		noError(t, err)
		if len(jobs.Jobs) != 2 {
			t.Fatal("implicit source transactions did not durably queue both operations")
		}
		for _, job := range jobs.Jobs {
			if job.State != rivertype.JobStateAvailable || strings.Contains(string(job.EncodedArgs), "credential") || strings.Contains(string(job.EncodedArgs), "127.0.0.1") {
				t.Fatal("source obligation is unavailable or contains transport credentials/configuration")
			}
		}
		page, err := f.auth.ListNotifications(t.Context(), u.ID, notify.ListOptions{})
		noError(t, err)
		if len(page.Items) != 0 {
			t.Fatal("remote producer wrote an inbox before worker delivery")
		}
	})
	t.Run("AK-J34-C01_transactional_publication_and_revisioned_withdrawal", func(t *testing.T) {
		f, sink, _ := notificationFixture(t)
		u := f.user(t)
		m := notificationChange(u.ID, "export:one", 1)
		tx, err := f.pool.Begin(t.Context())
		noError(t, err)
		noError(t, publishNotificationBatch(t.Context(), sink, []notify.Mutation{m}, tx))
		page, err := f.auth.ListNotifications(t.Context(), u.ID, notify.ListOptions{})
		noError(t, err)
		if len(page.Items) != 0 {
			t.Fatal("uncommitted notification escaped its domain transaction")
		}
		noError(t, tx.Rollback(t.Context()))
		noError(t, publishNotificationBatch(t.Context(), sink, []notify.Mutation{m}))
		page, err = f.auth.ListNotifications(t.Context(), u.ID, notify.ListOptions{})
		noError(t, err)
		if len(page.Items) != 1 {
			t.Fatal("committed notification is missing")
		}
		id := page.Items[0].ID
		_, err = f.auth.SetNotificationRead(t.Context(), u.ID, id, true)
		noError(t, err)
		noError(t, publishNotificationBatch(t.Context(), sink, []notify.Mutation{m}))
		item, err := f.auth.GetNotification(t.Context(), u.ID, id)
		noError(t, err)
		if item.ReadAt == nil {
			t.Fatal("producer replay reset user read state")
		}
		withdrawn := m
		withdrawn.Revision = 2
		withdrawn.Withdrawn = true
		noError(t, publishNotificationBatch(t.Context(), sink, []notify.Mutation{withdrawn}))
		noError(t, publishNotificationBatch(t.Context(), sink, []notify.Mutation{m}))
		page, err = f.auth.ListNotifications(t.Context(), u.ID, notify.ListOptions{UnreadOnly: true})
		noError(t, err)
		if len(page.Items) != 0 {
			t.Fatal("delayed publish resurrected a withdrawn notification")
		}
		_, err = f.auth.GetNotification(t.Context(), u.ID, id)
		if !errors.Is(err, notify.ErrNotFound) {
			t.Fatalf("withdrawn receipt remained addressable: %v", err)
		}
		m.Revision = 3
		noError(t, publishNotificationBatch(t.Context(), sink, []notify.Mutation{m}))
		item, err = f.auth.GetNotification(t.Context(), u.ID, id)
		noError(t, err)
		if item.ReadAt != nil {
			t.Fatal("newer reopen did not become unread")
		}
		conflict := m
		conflict.Data = json.RawMessage(`{"export_id":"conflict"}`)
		if err = publishNotificationBatch(t.Context(), sink, []notify.Mutation{conflict}); !errors.Is(err, notify.ErrConflict) {
			t.Fatalf("same-revision conflict accepted: %v", err)
		}
		late := notificationChange(u.ID, "export:late", 1)
		first := late
		first.Withdrawn = true
		first.Revision = 2
		noError(t, publishNotificationBatch(t.Context(), sink, []notify.Mutation{first}))
		noError(t, publishNotificationBatch(t.Context(), sink, []notify.Mutation{late}))
		page, err = f.auth.ListNotifications(t.Context(), u.ID, notify.ListOptions{})
		noError(t, err)
		if len(page.Items) != 1 || page.Items[0].ID != id {
			t.Fatal("withdraw-before-publish lost its tombstone")
		}
	})
	t.Run("AK-J34-C02_HTTP_receipts_are_private_and_producers_are_bound", func(t *testing.T) {
		f, sink, role := notificationFixture(t, multiTenant)
		alice, bob := f.user(t), f.user(t)
		m := notificationChange(alice.ID, "private:one", 1)
		noError(t, publishNotificationBatch(t.Context(), sink, []notify.Mutation{m}))
		a, b := f.signIn(t, alice), f.signIn(t, bob)
		f.call(t, "GET", "/me/notifications", "", nil).want(t, http.StatusUnauthorized, "")
		listed := f.call(t, "GET", "/me/notifications?recipient="+alice.ID, b.AccessToken, nil)
		listed.want(t, http.StatusOK, "")
		var page notify.Page
		decode(t, listed.body, &page)
		if len(page.Items) != 0 {
			t.Fatal("recipient query exposed another account")
		}
		listed = f.call(t, "GET", "/me/notifications", a.AccessToken, nil)
		listed.want(t, http.StatusOK, "")
		decode(t, listed.body, &page)
		if len(page.Items) != 1 {
			t.Fatal("owner cannot read valid control receipt")
		}
		id := page.Items[0].ID
		for _, path := range []string{"/me/notifications/" + id, "/me/notifications/" + id + "/read", "/me/notifications/" + id + "/dismiss"} {
			method := "PUT"
			if path == "/me/notifications/"+id {
				method = "GET"
			}
			f.call(t, method, path, b.AccessToken, nil).want(t, http.StatusNotFound, "not_found")
		}
		f.call(t, "PUT", "/me/notifications/"+id+"/read", a.AccessToken, nil).want(t, http.StatusOK, "")
		f.call(t, "PUT", "/me/notifications/"+id+"/dismiss", a.AccessToken, nil).want(t, http.StatusOK, "")
		active := f.call(t, "GET", "/me/notifications", a.AccessToken, nil)
		decode(t, active.body, &page)
		if len(page.Items) != 0 {
			t.Fatal("dismissed receipt remained active")
		}
		f.call(t, "DELETE", "/me/notifications/"+id+"/dismiss", a.AccessToken, nil).want(t, http.StatusOK, "")
		f.call(t, "DELETE", "/me/notifications/"+id+"/read", a.AccessToken, nil).want(t, http.StatusOK, "")
		body := map[string]any{"mutations": []notify.Mutation{notificationChange(alice.ID, "remote:one", 1)}}
		f.call(t, "POST", "/notifications/application", b.AccessToken, body).want(t, http.StatusForbidden, "")
		key, err := f.auth.CreateAPIKey(t.Context(), iam.SystemIdentity(), iam.GroupByID(f.tenant.String()), iam.NewAPIKey{Name: "notification sender", Role: role})
		noError(t, err)
		f.call(t, "POST", "/notifications/application", key.Secret, body).want(t, http.StatusNoContent, "")
		forged := notificationChange(alice.ID, "remote:forged", 1)
		forged.Origin.System = "openrails"
		f.call(t, "POST", "/notifications/application", key.Secret, map[string]any{"mutations": []notify.Mutation{forged}}).want(t, http.StatusForbidden, "")
		foreign := notificationChange(alice.ID, "remote:foreign", 1)
		foreign.AppID = iam.NewTenantID().String()
		f.call(t, "POST", "/notifications/application", key.Secret, map[string]any{"mutations": []notify.Mutation{foreign}}).want(t, http.StatusForbidden, "")
		noError(t, f.auth.RevokeAPIKey(t.Context(), iam.SystemIdentity(), iam.GroupByID(f.tenant.String()), key.APIKey.ID))
		f.call(t, "POST", "/notifications/application", key.Secret, body).want(t, http.StatusUnauthorized, "")
		otherID := iam.NewTenantID()
		noError(t, f.auth.CreateTenant(t.Context(), iam.Tenant{ID: otherID, Slug: "inbox-other"}))
		other, err := f.auth.ForTenant(t.Context(), otherID)
		noError(t, err)
		// The other tenant's own registration publishes only in its tenant.
		otherSink, err := other.Notifications(applicationProducer(otherID, f.notify))
		noError(t, err)
		noError(t, publishNotificationBatch(t.Context(), otherSink, []notify.Mutation{notificationChange(alice.ID, "other:one", 1)}))
		page, err = f.auth.ListNotifications(t.Context(), alice.ID, notify.ListOptions{Dismissed: true})
		noError(t, err)
		for _, item := range page.Items {
			if item.Origin.ID == "other:one" {
				t.Fatal("producer escaped its tenant")
			}
		}
	})
	t.Run("AK-J34-C03_remote_delivery_survives_rollback_restart_and_lost_response", func(t *testing.T) {
		f, _, role := notificationFixture(t)
		u := f.user(t)
		key, err := f.auth.CreateAPIKey(t.Context(), iam.SystemIdentity(), iam.GroupByID(f.tenant.String()), iam.NewAPIKey{Name: "notification delivery", Role: role})
		noError(t, err)
		var lose atomic.Bool
		lose.Store(true)
		transport := &lostNotificationResponse{next: http.DefaultTransport, lose: &lose}
		destinations := map[string]authkit.RemoteNotificationConfig{"accounts": {BaseURL: f.server.URL + f.auth.APIBase(), Producer: "application", Token: func(context.Context) (string, error) { return key.Secret, nil }, HTTPClient: &http.Client{Transport: transport}}}
		delivery, err := authkit.NewNotificationDelivery(f.pool, f.schema, destinations, nil)
		noError(t, err)
		sink, err := delivery.Publisher("accounts")
		noError(t, err)
		m := notificationChange(u.ID, "queued:one", 1)
		rollback, err := f.pool.Begin(t.Context())
		noError(t, err)
		noError(t, publishNotificationBatch(t.Context(), sink, []notify.Mutation{m}, rollback))
		noError(t, rollback.Rollback(t.Context()))
		tx, err := f.pool.Begin(t.Context())
		noError(t, err)
		noError(t, publishNotificationBatch(t.Context(), sink, []notify.Mutation{m}, tx))
		noError(t, tx.Commit(t.Context()))
		// Reconstruct the publisher/worker from configuration after the transaction
		// committed; queued work must not depend on the original Go object.
		restarted, err := authkit.NewNotificationDelivery(f.pool, f.schema, destinations, nil)
		noError(t, err)
		fleet, err := riverhelpers.New(t.Context(), f.pool, &river.Config{Schema: f.schema}, restarted.RiverJobs())
		noError(t, err)
		before, err := fleet.JobList(t.Context(), river.NewJobListParams().Kinds("authkit_notification_delivery").First(10))
		noError(t, err)
		if len(before.Jobs) != 1 {
			t.Fatal("rolled back remote obligation survived, or committed obligation disappeared")
		}
		noError(t, fleet.Start(context.Background()))
		t.Cleanup(func() {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			noError(t, fleet.Stop(ctx))
		})
		eventually(t, "destination commit before lost response", func() bool {
			page, err := f.auth.ListNotifications(t.Context(), u.ID, notify.ListOptions{})
			noError(t, err)
			return len(page.Items) == 1
		})
		page, err := f.auth.ListNotifications(t.Context(), u.ID, notify.ListOptions{})
		noError(t, err)
		id := page.Items[0].ID
		_, err = f.auth.SetNotificationRead(t.Context(), u.ID, id, true)
		noError(t, err)
		eventually(t, "failed delivery recorded for retry", func() bool {
			job, err := fleet.JobGet(t.Context(), before.Jobs[0].ID)
			noError(t, err)
			return job.State == rivertype.JobStateRetryable
		})
		lose.Store(false)
		_, err = fleet.JobRetry(t.Context(), before.Jobs[0].ID)
		noError(t, err)
		eventually(t, "replayed delivery completes", func() bool {
			job, err := fleet.JobGet(t.Context(), before.Jobs[0].ID)
			noError(t, err)
			return job.State == rivertype.JobStateCompleted
		})
		page, err = f.auth.ListNotifications(t.Context(), u.ID, notify.ListOptions{})
		noError(t, err)
		if len(page.Items) != 1 || page.Items[0].ID != id || page.Items[0].ReadAt == nil {
			t.Fatal("lost response replay duplicated or reset the receipt")
		}
	})

	t.Run("AK-J34-C04_the_inbox_lives_beside_the_accounts", func(t *testing.T) {
		f, sink, _ := notificationFixture(t)
		u := f.user(t)
		var tables int
		noError(t, f.pool.QueryRow(t.Context(), `SELECT count(*) FROM information_schema.tables WHERE table_schema = $1 AND table_name IN ('notify_items', 'notify_recipients', 'notify_app_erasures')`, f.schema).Scan(&tables))
		if tables != 3 {
			t.Fatalf("the account schema holds %d of the inbox's 3 tables", tables)
		}
		scope, err := f.auth.NotificationScope()
		noError(t, err)
		if scope != "authkit:"+f.tenant.String() {
			t.Fatalf("inbox scope %q is not the tenant's", scope)
		}
		// A replica that only validates the schema serves the same inbox.
		cfg := f.cfg
		cfg.Database.SkipMigrations = true
		replica, err := authkit.New(t.Context(), cfg, f.deps)
		noError(t, err)
		t.Cleanup(func() { noError(t, replica.Close(context.Background())) })
		noError(t, publishNotificationBatch(t.Context(), sink, []notify.Mutation{notificationChange(u.ID, "beside:one", 1)}))
		page, err := replica.ListNotifications(t.Context(), u.ID, notify.ListOptions{})
		noError(t, err)
		if len(page.Items) != 1 || page.Items[0].Origin.ID != "beside:one" {
			t.Fatal("a validating replica does not serve the inbox")
		}
	})

	t.Run("AK-J34-C06_exact_legacy_adoption_preserves_identity_and_never_replays_history", func(t *testing.T) {
		f, sink, _ := notificationFixtureWith(t, func(p *authkit.NotificationProducer) {
			p.Origin = notify.OriginScope{System: "openrails", Scope: "merchant"}
			p.Visibility = notify.VisibilityTenant
		})
		u := f.user(t)
		scope, err := f.auth.NotificationScope()
		noError(t, err)
		store, err := notifypg.New(f.pool, notifypg.Config{Schema: f.schema, Scope: scope})
		noError(t, err)
		current := notificationChange(u.ID, "issue:payment-method", 1)
		current.Origin.System, current.Origin.Scope = "openrails", "merchant"
		current.Visibility, current.AppID = notify.VisibilityTenant, ""
		current.Kind = "payment_method_failed"
		current.ActionRequested = true
		older := current.Input
		older.Origin.Subject, older.Status = "legacy-customer", notify.StatusOpen
		older.Visibility = ""
		older.Origin.ID = "ntf_older"
		older.CreatedAt = current.CreatedAt.Add(-time.Hour)
		newest := current.Input
		newest.Origin.Subject, newest.Status = "legacy-customer", notify.StatusOpen
		newest.Visibility = ""
		newest.Origin.ID = "ntf_newest"
		newest.CreatedAt = current.CreatedAt.Add(-time.Minute)
		oldItem, err := store.Publish(t.Context(), older)
		noError(t, err)
		item, err := store.Publish(t.Context(), newest)
		noError(t, err)
		_, err = store.SetRead(t.Context(), item.Recipient, item.ID, true)
		noError(t, err)
		_, err = store.SetDismissed(t.Context(), item.Recipient, item.ID, true)
		noError(t, err)
		mapping := notify.Adoption{Previous: []notify.Origin{newest.Origin, older.Origin}, Current: current}
		noError(t, f.auth.AdoptNotifications(t.Context(), "application", []notify.Adoption{mapping}))
		noError(t, f.auth.AdoptNotifications(t.Context(), "application", []notify.Adoption{mapping}))
		noError(t, publishNotificationBatch(t.Context(), sink, []notify.Mutation{current}))
		adopted, err := f.auth.GetNotification(t.Context(), u.ID, item.ID)
		noError(t, err)
		if adopted.Origin.ID != current.Origin.ID || adopted.ReadAt == nil || adopted.DismissedAt == nil {
			t.Fatal("exact adoption changed identity or reset user receipt state")
		}
		_, err = f.auth.GetNotification(t.Context(), u.ID, oldItem.ID)
		if !errors.Is(err, notify.ErrNotFound) {
			t.Fatal("redundant legacy receipt remained visible")
		}
		absent := current
		absent.Origin.ID = "unconsumed:history"
		noError(t, f.auth.AdoptNotifications(t.Context(), "application", []notify.Adoption{{Current: absent}}))
		page, err := f.auth.ListNotifications(t.Context(), u.ID, notify.ListOptions{})
		noError(t, err)
		if len(page.Items) != 0 {
			t.Fatal("adoption replayed unconsumed history")
		}
		newer := current
		newer.Revision = 2
		newer.Withdrawn = true
		noError(t, publishNotificationBatch(t.Context(), sink, []notify.Mutation{newer}))
		noError(t, f.auth.AdoptNotifications(t.Context(), "application", []notify.Adoption{mapping}))
		_, err = f.auth.GetNotification(t.Context(), u.ID, item.ID)
		if !errors.Is(err, notify.ErrNotFound) {
			t.Fatal("migration replay lowered a canonical producer revision")
		}
		foreign := current.Input
		foreign.Origin.ID = "ntf_foreign_app"
		foreign.Visibility = notify.VisibilityApp
		foreign.AppID = "another-app"
		foreignItem, err := store.Publish(t.Context(), foreign)
		noError(t, err)
		attempted := current
		attempted.Origin.ID = "issue:foreign"
		err = f.auth.AdoptNotifications(t.Context(), "application", []notify.Adoption{{Previous: []notify.Origin{foreign.Origin}, Current: attempted}})
		if !errors.Is(err, notify.ErrConflict) {
			t.Fatalf("adoption relabeled an explicit foreign app: %v", err)
		}
		retained, err := store.Get(t.Context(), foreign.Recipient, foreignItem.ID)
		noError(t, err)
		if retained.Origin.ID != foreign.Origin.ID || retained.Visibility != notify.VisibilityApp || retained.AppID != foreign.AppID {
			t.Fatal("refused adoption changed a foreign receipt")
		}
		versioned := current
		versioned.Origin.ID = "issue:versioned-unclassified"
		versioned.Visibility = ""
		old, err := store.Publish(t.Context(), versioned.Input)
		noError(t, err)
		noError(t, store.Apply(t.Context(), []notify.Mutation{versioned}))
		classified := versioned
		classified.Visibility = notify.VisibilityTenant
		classified.Revision = 2
		err = f.auth.AdoptNotifications(t.Context(), "application", []notify.Adoption{{Current: classified}})
		if !errors.Is(err, notify.ErrConflict) {
			t.Fatalf("adoption changed a versioned unclassified identity: %v", err)
		}
		unchanged, err := store.Get(t.Context(), old.Recipient, old.ID)
		noError(t, err)
		if unchanged.Visibility != "" || unchanged.ProducerRevision != 1 {
			t.Fatal("refused classification changed producer state")
		}

	})
	t.Run("AK-J34-C07_account_purge_fences_delayed_delivery", func(t *testing.T) {
		f, sink, _ := notificationFixture(t)
		f.startFleet(t)
		u := f.user(t)
		m := notificationChange(u.ID, "account:purged", 1)
		noError(t, publishNotificationBatch(t.Context(), sink, []notify.Mutation{m}))
		scope, err := f.auth.NotificationScope()
		noError(t, err)
		rows, err := f.auth.PurgeUsers(t.Context(), []string{u.ID})
		goodBatch(t, rows, err)
		f.purged(t, u.ID)
		noError(t, publishNotificationBatch(t.Context(), sink, []notify.Mutation{m}))
		store, err := notifypg.New(f.pool, notifypg.Config{Schema: f.schema, Scope: scope})
		noError(t, err)
		page, err := store.List(t.Context(), m.Recipient, notify.ListOptions{})
		noError(t, err)
		if len(page.Items) != 0 {
			t.Fatal("purged account retained notifications")
		}
		if _, err = store.Publish(t.Context(), m.Input); !errors.Is(err, notify.ErrRecipientErased) {
			t.Fatalf("account purge failed to fence a legacy producer: %v", err)
		}
	})
	t.Run("AK-J34-C08_withdrawal_during_recoverable_deletion_survives_restore", func(t *testing.T) {
		f, sink, _ := notificationFixture(t)
		u := f.user(t)
		m := notificationChange(u.ID, "account:restore", 1)
		noError(t, publishNotificationBatch(t.Context(), sink, []notify.Mutation{m}))
		results, err := f.auth.DeleteUsers(t.Context(), iam.SystemIdentity(), []string{u.ID})
		goodBatch(t, results, err)
		withdrawn := m
		withdrawn.Revision = 2
		withdrawn.Withdrawn = true
		noError(t, publishNotificationBatch(t.Context(), sink, []notify.Mutation{withdrawn}))
		results, err = f.auth.RestoreUsers(t.Context(), iam.SystemIdentity(), []string{u.ID})
		goodBatch(t, results, err)
		noError(t, publishNotificationBatch(t.Context(), sink, []notify.Mutation{m}))
		page, err := f.auth.ListNotifications(t.Context(), u.ID, notify.ListOptions{})
		noError(t, err)
		if len(page.Items) != 0 {
			t.Fatal("restore resurrected a resolved notification")
		}
	})

	t.Run("AK-J34-C09_source_transaction_keeps_its_search_path_and_uncommitted_account", func(t *testing.T) {
		f, sink, _ := notificationFixture(t)
		cfg := f.pool.Config()
		cfg.MaxConns = 1
		source, err := pgxpool.NewWithConfig(t.Context(), cfg)
		noError(t, err)
		defer source.Close()
		tx, err := source.Begin(t.Context())
		noError(t, err)
		defer tx.Rollback(context.Background())
		_, err = tx.Exec(t.Context(), `SET LOCAL search_path = pg_catalog`)
		noError(t, err)
		u, err := f.auth.CreateUser(t.Context(), iam.NewUser{Username: "transactionuser", Email: "transaction-user@example.test", EmailVerified: true}, authkit.InTx(tx))
		noError(t, err)
		m := notificationChange(u.ID, "transaction:created", 1)
		ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
		defer cancel()
		noError(t, publishNotificationBatch(ctx, sink, []notify.Mutation{m}, tx))
		var searchPath string
		noError(t, tx.QueryRow(t.Context(), `SELECT current_setting('search_path')`).Scan(&searchPath))
		if searchPath != "pg_catalog" {
			t.Fatalf("publisher changed caller search_path: %s", searchPath)
		}
		noError(t, tx.Commit(t.Context()))
		page, err := f.auth.ListNotifications(t.Context(), u.ID, notify.ListOptions{})
		noError(t, err)
		if len(page.Items) != 1 {
			t.Fatal("publisher did not read the account created in its source transaction")
		}
	})

	t.Run("AK-J34-C10_local_and_remote_publications_reuse_one_connection", func(t *testing.T) {
		var connections atomic.Int32
		var source *pgxpool.Pool
		f, accountSink, _ := notificationFixture(t, authtest.WithDeps(func(d *authkit.Deps) {
			cfg := d.Postgres.Config()
			cfg.MaxConns = 1
			cfg.BeforeConnect = func(context.Context, *pgx.ConnConfig) error {
				connections.Add(1)
				return nil
			}
			var err error
			source, err = pgxpool.NewWithConfig(t.Context(), cfg)
			noError(t, err)
			t.Cleanup(source.Close)
			d.Postgres = source
		}))
		u := f.user(t)
		destination := map[string]authkit.RemoteNotificationConfig{"accounts": {BaseURL: f.server.URL + f.auth.APIBase(), Producer: "application", Token: func(context.Context) (string, error) { return "not-needed-for-queue", nil }}}
		delivery, err := authkit.NewNotificationDelivery(source, f.schema, destination, nil)
		noError(t, err)
		sink, err := delivery.Publisher("accounts")
		noError(t, err)
		reader, err := river.NewClient(riverpgxv5.New(source), &river.Config{Schema: f.schema})
		noError(t, err)
		noError(t, source.Ping(t.Context()))
		before := connections.Load()
		for name, publisher := range map[string]notify.Publisher{"local": accountSink, "remote": sink} {
			for _, commit := range []bool{false, true} {
				tx, err := source.Begin(t.Context())
				noError(t, err)
				m := notificationChange(u.ID, fmt.Sprintf("%s:commit:%t", name, commit), 1)
				err = publishNotificationBatch(t.Context(), publisher, []notify.Mutation{m}, tx)
				if err != nil {
					_ = tx.Rollback(context.Background())
					noError(t, err)
				}
				if commit {
					noError(t, tx.Commit(t.Context()))
				} else {
					noError(t, tx.Rollback(t.Context()))
				}
			}
			noError(t, publishNotificationBatch(t.Context(), publisher, []notify.Mutation{notificationChange(u.ID, name+":implicit", 1)}))
		}
		page, err := f.auth.ListNotifications(t.Context(), u.ID, notify.ListOptions{})
		noError(t, err)
		if len(page.Items) != 2 {
			t.Fatalf("local publications did not follow commit/rollback: %+v", page.Items)
		}
		jobs, err := reader.JobList(t.Context(), river.NewJobListParams().Kinds("authkit_notification_delivery"))
		noError(t, err)
		if len(jobs.Jobs) != 2 {
			t.Fatalf("remote obligations did not follow commit/rollback: %+v", jobs.Jobs)
		}
		if after := connections.Load(); after != before {
			t.Fatalf("publication opened %d additional database connections", after-before)
		}
	})
	t.Run("AK-J34-C11_maximum_HTML_batch_delivers_and_oversize_is_not_queued", func(t *testing.T) {
		f, _, role := notificationFixture(t)
		u := f.user(t)
		key, err := f.auth.CreateAPIKey(t.Context(), iam.SystemIdentity(), iam.GroupByID(f.tenant.String()), iam.NewAPIKey{Name: "large batch sender", Role: role})
		noError(t, err)
		delivery, err := authkit.NewNotificationDelivery(f.pool, f.schema, map[string]authkit.RemoteNotificationConfig{"accounts": {BaseURL: f.server.URL + f.auth.APIBase(), Producer: "application", Token: func(context.Context) (string, error) { return key.Secret, nil }, HTTPClient: &http.Client{Timeout: time.Minute}}}, nil)
		noError(t, err)
		sink, err := delivery.Publisher("accounts")
		noError(t, err)
		payload := json.RawMessage(`{"html":"` + strings.Repeat("<", (64<<10)-len(`{"html":""}`)) + `"}`)
		batch := make([]notify.Mutation, notify.MaxMutations)
		for i := range batch {
			batch[i] = notificationChange(u.ID, fmt.Sprintf("large:%d", i), 1)
			batch[i].Data = payload
		}
		noError(t, publishNotificationBatch(t.Context(), sink, batch))
		// Omitted transactions still enqueue remote work. Nothing reaches the
		// destination until its ordinary source fleet executes the obligation.
		page, err := f.auth.ListNotifications(t.Context(), u.ID, notify.ListOptions{Limit: 100})
		noError(t, err)
		if len(page.Items) != 0 {
			t.Fatal("remote publication bypassed its durable source queue")
		}
		fleet, err := riverhelpers.New(t.Context(), f.pool, &river.Config{Schema: f.schema}, delivery.RiverJobs())
		noError(t, err)
		noError(t, fleet.Start(context.Background()))
		t.Cleanup(func() {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			noError(t, fleet.Stop(ctx))
		})
		eventually(t, "maximum batch arrives through the durable worker", func() bool {
			page, err = f.auth.ListNotifications(t.Context(), u.ID, notify.ListOptions{Limit: 100})
			noError(t, err)
			return len(page.Items) == notify.MaxMutations
		})
		page, err = f.auth.ListNotifications(t.Context(), u.ID, notify.ListOptions{Limit: 100})
		noError(t, err)
		if len(page.Items) != notify.MaxMutations {
			t.Fatal("valid maximum batch was truncated or rejected")
		}
		tx, err := f.pool.Begin(t.Context())
		noError(t, err)
		excessive := append(append([]notify.Mutation(nil), batch...), batch[0])
		if err = publishNotificationBatch(t.Context(), sink, excessive, tx); !errors.Is(err, notify.ErrInvalid) {
			t.Fatalf("over-bound batch accepted for durable retry: %v", err)
		}
		oversized := batch[0]
		oversized.Data = json.RawMessage(`{"html":"` + strings.Repeat("<", 64<<10) + `"}`)
		if err = publishNotificationBatch(t.Context(), sink, []notify.Mutation{oversized}, tx); !errors.Is(err, notify.ErrInvalid) {
			t.Fatalf("over-bound payload accepted for durable retry: %v", err)
		}
		noError(t, tx.Commit(t.Context()))
	})
	t.Run("AK-J34-C14_public_publisher_operations_share_transactions_and_reject_partial_batches", func(t *testing.T) {
		f, publisher, _ := notificationFixture(t)
		u := f.user(t)
		publication := notify.Publication{RecipientID: u.ID, ID: "batch:seed", Revision: 1, Kind: "export.ready", Data: json.RawMessage(`{"ready":true}`), CreatedAt: time.Now().UTC()}
		noError(t, publisher.Publish(t.Context(), []notify.Publication{publication}))
		tx, err := f.pool.Begin(t.Context())
		noError(t, err)
		if err := publisher.Publish(t.Context(), nil, nil); !errors.Is(err, notify.ErrInvalid) {
			t.Fatalf("explicit nil transaction accepted: %v", err)
		}
		if err := publisher.Withdraw(t.Context(), nil, tx, tx); !errors.Is(err, notify.ErrInvalid) {
			t.Fatalf("multiple transactions accepted: %v", err)
		}
		other := publication
		other.ID = "batch:rollback"
		noError(t, publisher.Publish(t.Context(), []notify.Publication{other}, tx))
		noError(t, publisher.Withdraw(t.Context(), []notify.Withdrawal{{RecipientID: u.ID, ID: publication.ID, Revision: 2}}, tx))
		noError(t, tx.Rollback(t.Context()))
		page, err := f.auth.ListNotifications(t.Context(), u.ID, notify.ListOptions{})
		noError(t, err)
		if len(page.Items) != 1 || page.Items[0].Origin.ID != publication.ID {
			t.Fatal("publish and withdrawal escaped their shared rollback")
		}
		noError(t, pgx.BeginFunc(t.Context(), f.pool, func(tx pgx.Tx) error {
			_, err := tx.Exec(t.Context(), "CREATE TABLE "+pgx.Identifier{f.schema, "notification_domain_marker"}.Sanitize()+" (id integer PRIMARY KEY)")
			if err != nil {
				return err
			}
			_, err = tx.Exec(t.Context(), "INSERT INTO "+pgx.Identifier{f.schema, "notification_domain_marker"}.Sanitize()+" VALUES (1)")
			if err != nil {
				return err
			}
			conflict := publication
			conflict.Data = json.RawMessage(`{"ready":false}`)
			if err = publisher.Publish(t.Context(), []notify.Publication{other, conflict}, tx); !errors.Is(err, notify.ErrConflict) {
				return fmt.Errorf("conflicting batch returned %v", err)
			}
			return nil
		}))
		var markers int
		noError(t, f.pool.QueryRow(t.Context(), "SELECT count(*) FROM "+pgx.Identifier{f.schema, "notification_domain_marker"}.Sanitize()).Scan(&markers))
		page, err = f.auth.ListNotifications(t.Context(), u.ID, notify.ListOptions{})
		noError(t, err)
		if markers != 1 || len(page.Items) != 1 || page.Items[0].Origin.ID != publication.ID {
			t.Fatal("failed batch leaked an item or aborted the caller's independent work")
		}
	})
	t.Run("AK-J34-C12_app_erasure_does_not_suppress_tenant_billing_notices", func(t *testing.T) {
		f, app, _ := notificationFixture(t)
		u := f.user(t)
		scope, err := f.auth.NotificationScope()
		noError(t, err)
		store, err := notifypg.New(f.pool, notifypg.Config{Schema: f.schema, Scope: scope})
		noError(t, err)
		recipient := notify.Recipient{Audience: notify.AudienceUser, ID: u.ID}
		// An old origin-only fence remains authoritative for its newly classified
		// application, but cannot withdraw unrelated tenant-wide billing notices.
		noError(t, store.EraseAppRecipient(t.Context(), recipient, "", notify.OriginScope{System: "application", Scope: "app"}))
		noError(t, publishNotificationBatch(t.Context(), app, []notify.Mutation{notificationChange(u.ID, "app:erased", 1)}))
		billing, err := f.auth.Notifications(authkit.NotificationProducer{Name: "billing", Origin: notify.OriginScope{System: "billing", Scope: "merchant"}, Visibility: notify.VisibilityTenant})
		noError(t, err)
		notice := notificationChange(u.ID, "billing:active", 1)
		notice.Origin.System = "billing"
		notice.Origin.Scope = "merchant"
		notice.Visibility = notify.VisibilityTenant
		notice.AppID = ""
		noError(t, publishNotificationBatch(t.Context(), billing, []notify.Mutation{notice}))
		page, err := f.auth.ListNotifications(t.Context(), u.ID, notify.ListOptions{})
		noError(t, err)
		if len(page.Items) != 1 || page.Items[0].Origin.System != "billing" {
			t.Fatal("legacy app erasure hid billing or allowed its own app to republish")
		}
		noError(t, store.EraseAppRecipient(t.Context(), recipient, notificationApp, notify.OriginScope{}))
		noError(t, publishNotificationBatch(t.Context(), app, []notify.Mutation{notificationChange(u.ID, "app:explicit-erased", 1)}))
		page, err = f.auth.ListNotifications(t.Context(), u.ID, notify.ListOptions{})
		noError(t, err)
		if len(page.Items) != 1 || page.Items[0].Origin.System != "billing" {
			t.Fatal("explicit app erasure affected tenant billing")
		}
	})

	t.Run("AK-J34-C13_each_tenant_has_its_own_inbox", func(t *testing.T) {
		f, sink, _ := notificationFixture(t, multiTenant)
		alice := f.user(t)
		noError(t, publishNotificationBatch(t.Context(), sink, []notify.Mutation{notificationChange(alice.ID, "ownership:alice", 1)}))
		other := iam.NewTenantID()
		noError(t, f.auth.CreateTenant(t.Context(), iam.Tenant{ID: other, Slug: "inbox-foreign"}))
		view, err := f.auth.ForTenant(t.Context(), other)
		noError(t, err)
		bob := authtest.NewUser(t, view)
		otherSink, err := view.Notifications(applicationProducer(other, f.notify))
		noError(t, err)
		noError(t, publishNotificationBatch(t.Context(), otherSink, []notify.Mutation{notificationChange(bob.ID, "ownership:bob", 1)}))
		mine, err := f.auth.NotificationScope()
		noError(t, err)
		theirs, err := view.NotificationScope()
		noError(t, err)
		if mine == theirs {
			t.Fatal("two tenants share an inbox scope")
		}
		page, err := f.auth.ListNotifications(t.Context(), alice.ID, notify.ListOptions{})
		noError(t, err)
		if len(page.Items) != 1 || page.Items[0].Recipient.ID != alice.ID {
			t.Fatal("another tenant's publication reached this inbox")
		}
		if _, err = view.ListNotifications(t.Context(), alice.ID, notify.ListOptions{}); !errors.Is(err, iam.ErrUserNotFound) {
			t.Fatalf("another tenant read this account's inbox: %v", err)
		}
	})
	t.Run("AK-J34-C05_producers_register_by_call", func(t *testing.T) {
		f := newFixture(t)
		u := f.user(t)
		session := f.signIn(t, u)
		// The inbox is built in, empty until a producer publishes.
		listed := f.call(t, "GET", "/me/notifications", session.AccessToken, nil)
		listed.want(t, http.StatusOK, "")
		body := map[string]any{"mutations": []notify.Mutation{notificationChange(u.ID, "unregistered:one", 1)}}
		f.call(t, "POST", "/notifications/application", session.AccessToken, body).want(t, http.StatusForbidden, "")
		producer := authkit.NotificationProducer{Name: "application", Origin: notify.OriginScope{System: "application", Scope: "app"}}
		first, err := f.auth.Notifications(producer)
		noError(t, err)
		again, err := f.auth.Notifications(producer)
		noError(t, err)
		if first == nil || again == nil {
			t.Fatal("registering a producer again returned no publisher")
		}
		producer.Origin.Scope = "another"
		if _, err := f.auth.Notifications(producer); err == nil {
			t.Fatal("a second binding took an existing producer's name")
		}
		if _, err := f.auth.Notifications(authkit.NotificationProducer{Name: "Bad Name", Origin: producer.Origin}); err == nil {
			t.Fatal("an invalid producer registered")
		}
	})
}

type lostNotificationResponse struct {
	next http.RoundTripper
	lose *atomic.Bool
}

func (t *lostNotificationResponse) RoundTrip(r *http.Request) (*http.Response, error) {
	res, err := t.next.RoundTrip(r)
	if err == nil && res.StatusCode == http.StatusNoContent && t.lose.Load() {
		_ = res.Body.Close()
		return nil, errors.New("test: response lost after committed destination write")
	}
	return res, err
}
