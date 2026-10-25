package critical_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/open-rails/authkit"
	"github.com/open-rails/authkit/auth"
	"github.com/open-rails/authkit/authtest"
	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/notify"
	notifypg "github.com/open-rails/authkit/notify/postgres"
	riverhelpers "github.com/open-rails/helpers/river"
	"github.com/riverqueue/river"
	"github.com/riverqueue/river/riverdriver/riverpgxv5"
	"github.com/riverqueue/river/rivertype"
)

const notificationApp = "00000000-0000-4000-8000-000000000470"

func notificationFixture(t *testing.T, options ...authtest.Option) (*fixture, notify.Publisher, iam.Role) {
	t.Helper()
	roles := authkit.NewRoles(authkit.APIKeys, authkit.CustomRoles)
	permission := roles.Tenant.Permission("notifications", "publish")
	role := roles.Tenant.Role("notificationpublisher", permission)
	base := authtest.WithConfig(func(c *authkit.Config) {
		c.Roles = roles
		c.Notifications = &authkit.NotificationsConfig{Schema: c.Database.Schema, AppID: notificationApp, Producers: []authkit.NotificationProducer{{
			Name: "application", TenantID: c.DefaultTenantID, Origin: notify.OriginScope{System: "application", Scope: "app"}, Visibility: notify.VisibilityApp, AppID: notificationApp,
			PermissionGroupID: c.DefaultTenantID.String(), Permission: permission.String(),
		}}}
	})
	f := newFixture(t, append([]authtest.Option{base}, options...)...)
	sink, err := f.auth.Notifications("application")
	noError(t, err)
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
		}})
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
		f, sink, role := notificationFixture(t)
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
		noError(t, f.auth.CreateTenant(t.Context(), iam.Tenant{ID: otherID}))
		other, err := f.auth.ForTenant(t.Context(), otherID)
		noError(t, err)
		_, err = other.Notifications("application")
		if !errors.Is(err, auth.ErrForbidden) {
			t.Fatalf("producer escaped selected tenant: %v", err)
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
		delivery, err := authkit.NewNotificationDelivery(f.pool, f.schema, destinations)
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
		restarted, err := authkit.NewNotificationDelivery(f.pool, f.schema, destinations)
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

	t.Run("AK-J34-C04_existing_scope_adoption_preserves_receipts_and_erasure", func(t *testing.T) {
		f := newFixture(t)
		u := f.user(t)
		m := notificationChange(u.ID, "migration:one", 1)
		const scope = "contentkit:accounts"
		noError(t, notifypg.Migrate(t.Context(), f.pool, f.schema))
		store, err := notifypg.New(f.pool, notifypg.Config{Schema: f.schema, Scope: scope})
		noError(t, err)
		item, err := store.Publish(t.Context(), m.Input)
		noError(t, err)
		id := item.ID
		_, err = store.SetRead(t.Context(), item.Recipient, id, true)
		noError(t, err)
		_, err = store.SetDismissed(t.Context(), item.Recipient, id, true)
		noError(t, err)
		cfg := f.cfg
		cfg.Database.SkipMigrations = true
		cfg.Notifications = &authkit.NotificationsConfig{Schema: f.schema, Scopes: map[string]string{f.tenant.String(): scope}, AppID: notificationApp, Producers: []authkit.NotificationProducer{{Name: "application", TenantID: f.tenant, Origin: notify.OriginScope{System: "application", Scope: "app"}, Visibility: notify.VisibilityApp, AppID: notificationApp}}}
		noError(t, authkit.MigrateNotifications(t.Context(), f.pool, cfg))
		adopted, err := authkit.New(t.Context(), cfg, f.deps)
		noError(t, err)
		t.Cleanup(func() { noError(t, adopted.Close(context.Background())) })
		actual, err := adopted.NotificationScope()
		noError(t, err)
		if actual != scope {
			t.Fatal("legacy logical namespace was silently replaced")
		}
		archived, err := adopted.ListNotifications(t.Context(), u.ID, notify.ListOptions{Dismissed: true})
		noError(t, err)
		if len(archived.Items) != 1 || archived.Items[0].ID != id || archived.Items[0].ReadAt == nil || archived.Items[0].DismissedAt == nil {
			t.Fatal("adoption lost retained inbox state")
		}
		noError(t, store.EraseRecipient(t.Context(), item.Recipient))
		sink, err := adopted.Notifications("application")
		noError(t, err)
		m.Revision = 2
		noError(t, publishNotificationBatch(t.Context(), sink, []notify.Mutation{m}))
		page, err := adopted.ListNotifications(t.Context(), u.ID, notify.ListOptions{})
		noError(t, err)
		if len(page.Items) != 0 {
			t.Fatal("delayed notification resurrected an erased inbox")
		}
	})

	t.Run("AK-J34-C06_exact_legacy_adoption_preserves_identity_and_never_replays_history", func(t *testing.T) {
		f, sink, _ := notificationFixture(t, authtest.WithConfig(func(c *authkit.Config) {
			c.Notifications.Producers[0].Origin = notify.OriginScope{System: "openrails", Scope: "merchant"}
			c.Notifications.Producers[0].Visibility = notify.VisibilityTenant
			c.Notifications.Producers[0].AppID = ""
		}))
		u := f.user(t)
		scope, err := f.auth.NotificationScope()
		noError(t, err)
		store, err := notifypg.New(f.pool, notifypg.Config{Schema: f.schema, Scope: scope})
		noError(t, err)
		current := notificationChange(u.ID, "issue:payment-method", 1)
		current.Origin.System, current.Origin.Scope = "openrails", "merchant"
		current.Visibility, current.AppID = notify.VisibilityTenant, ""
		current.Kind = "payment_method_failed"
		older := current.Input
		older.Visibility = ""
		older.Origin.ID = "ntf_older"
		older.CreatedAt = current.CreatedAt.Add(-time.Hour)
		newest := current.Input
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

	t.Run("AK-J34-C10_local_and_remote_publishers_reject_foreign_database_transaction", func(t *testing.T) {
		f, accountSink, _ := notificationFixture(t)
		u := f.user(t)
		destination := map[string]authkit.RemoteNotificationConfig{"accounts": {BaseURL: f.server.URL + f.auth.APIBase(), Producer: "application", Token: func(context.Context) (string, error) { return "not-needed-for-queue", nil }}}
		delivery, err := authkit.NewNotificationDelivery(f.pool, f.schema, destination)
		noError(t, err)
		sink, err := delivery.Publisher("accounts")
		noError(t, err)
		cfg := f.pool.Config()
		cfg.MaxConns = 1
		if cfg.ConnConfig.Database == "postgres" {
			cfg.ConnConfig.Database = "template1"
		} else {
			cfg.ConnConfig.Database = "postgres"
		}
		other, err := pgxpool.NewWithConfig(t.Context(), cfg)
		noError(t, err)
		defer other.Close()
		noError(t, riverhelpers.ApplyMigrations(t.Context(), other, f.schema))
		defer func() {
			_, err := other.Exec(context.Background(), "DROP SCHEMA "+pgx.Identifier{f.schema}.Sanitize()+" CASCADE")
			noError(t, err)
		}()
		tx, err := other.Begin(t.Context())
		noError(t, err)
		defer tx.Rollback(context.Background())
		err = publishNotificationBatch(t.Context(), sink, []notify.Mutation{notificationChange(u.ID, "foreign:queue", 1)}, tx)
		if err == nil {
			t.Fatal("delivery accepted an obligation in another database")
		}
		noError(t, tx.Commit(t.Context()))
		reader, err := river.NewClient(riverpgxv5.New(other), &river.Config{Schema: f.schema})
		noError(t, err)
		jobs, err := reader.JobList(t.Context(), river.NewJobListParams().Kinds("authkit_notification_delivery"))
		noError(t, err)
		if len(jobs.Jobs) != 0 {
			t.Fatal("refused foreign transaction stranded a delivery job")
		}
		// A restored database can have the exact same tenant, account UUID,
		// schema and inbox ownership rows. Those rows cannot prove that the
		// caller's transaction belongs to the configured account database.
		clonedDeps := f.deps
		clonedDeps.Postgres = other
		clone, err := authkit.New(t.Context(), f.cfg, clonedDeps)
		noError(t, err)
		defer clone.Close(context.Background())
		imported, err := clone.ImportUsers(t.Context(), []iam.ImportUser{{ID: u.ID, Username: "clonedaccount"}}, iam.ImportOptions{})
		noError(t, err)
		if imported.Inserted != 1 {
			t.Fatalf("restore control account: %+v", imported)
		}
		tx, err = other.Begin(t.Context())
		noError(t, err)
		defer tx.Rollback(context.Background())
		refused := publishNotificationBatch(t.Context(), accountSink, []notify.Mutation{notificationChange(u.ID, "foreign:inbox", 1)}, tx)
		noError(t, tx.Commit(t.Context()))
		foreignInbox, err := clone.ListNotifications(t.Context(), u.ID, notify.ListOptions{})
		noError(t, err)
		accountInbox, err := f.auth.ListNotifications(t.Context(), u.ID, notify.ListOptions{})
		noError(t, err)
		if refused == nil || len(foreignInbox.Items) != 0 || len(accountInbox.Items) != 0 {
			t.Fatalf("local publisher accepted a cloned foreign database: error=%v, foreign=%d, configured=%d", refused, len(foreignInbox.Items), len(accountInbox.Items))
		}
		oneConfig := f.pool.Config()
		oneConfig.MaxConns = 1
		one, err := pgxpool.NewWithConfig(t.Context(), oneConfig)
		noError(t, err)
		defer one.Close()
		local, err := authkit.NewNotificationDelivery(one, f.schema, destination)
		noError(t, err)
		localSink, err := local.Publisher("accounts")
		noError(t, err)
		tx, err = one.Begin(t.Context())
		noError(t, err)
		noError(t, publishNotificationBatch(t.Context(), localSink, []notify.Mutation{notificationChange(u.ID, "local:queue", 1)}, tx))
		noError(t, tx.Rollback(t.Context()))
	})
	t.Run("AK-J34-C11_maximum_HTML_batch_delivers_and_oversize_is_not_queued", func(t *testing.T) {
		f, _, role := notificationFixture(t)
		u := f.user(t)
		key, err := f.auth.CreateAPIKey(t.Context(), iam.SystemIdentity(), iam.GroupByID(f.tenant.String()), iam.NewAPIKey{Name: "large batch sender", Role: role})
		noError(t, err)
		delivery, err := authkit.NewNotificationDelivery(f.pool, f.schema, map[string]authkit.RemoteNotificationConfig{"accounts": {BaseURL: f.server.URL + f.auth.APIBase(), Producer: "application", Token: func(context.Context) (string, error) { return key.Secret, nil }, HTTPClient: &http.Client{Timeout: time.Minute}}})
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
		f, app, _ := notificationFixture(t, authtest.WithConfig(func(c *authkit.Config) {
			c.Notifications.Producers = append(c.Notifications.Producers, authkit.NotificationProducer{Name: "billing", TenantID: c.DefaultTenantID, Origin: notify.OriginScope{System: "billing", Scope: "merchant"}, Visibility: notify.VisibilityTenant})
		}))
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
		billing, err := f.auth.Notifications("billing")
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

	t.Run("AK-J34-C13_separate_instances_cannot_alias_another_tenants_inbox", func(t *testing.T) {
		f, sink, _ := notificationFixture(t, authtest.WithConfig(func(c *authkit.Config) {
			c.Notifications.Scopes = map[string]string{c.DefaultTenantID.String(): "contentkit:accounts"}
		}))
		alice := f.user(t)
		noError(t, publishNotificationBatch(t.Context(), sink, []notify.Mutation{notificationChange(alice.ID, "ownership:alice", 1)}))
		other := iam.NewTenantID()
		noError(t, f.auth.CreateTenant(t.Context(), iam.Tenant{ID: other}))
		cfg := f.cfg
		cfg.DefaultTenantID = other
		n := *cfg.Notifications
		n.Scopes = map[string]string{other.String(): "contentkit:accounts"}
		n.Producers = append([]authkit.NotificationProducer(nil), n.Producers...)
		for i := range n.Producers {
			n.Producers[i].TenantID = other
			n.Producers[i].PermissionGroupID = other.String()
		}
		cfg.Notifications = &n
		if err := authkit.MigrateNotifications(t.Context(), f.pool, cfg); !errors.Is(err, authkit.ErrNotificationScopeConflict) {
			t.Fatalf("explicit migration aliased another tenant's inbox: %v", err)
		}
		cfg.Database.SkipMigrations = true
		refused, err := authkit.New(t.Context(), cfg, f.deps)
		if refused != nil {
			noError(t, refused.Close(context.Background()))
		}
		if !errors.Is(err, authkit.ErrNotificationScopeConflict) {
			t.Fatalf("separate runtime aliased another tenant's inbox: %v", err)
		}
		n.Scopes = nil
		allowed, err := authkit.New(t.Context(), cfg, f.deps)
		noError(t, err)
		defer allowed.Close(context.Background())
		bob := authtest.NewUser(t, allowed)
		otherSink, err := allowed.Notifications("application")
		noError(t, err)
		noError(t, publishNotificationBatch(t.Context(), otherSink, []notify.Mutation{notificationChange(bob.ID, "ownership:bob", 1)}))
		page, err := f.auth.ListNotifications(t.Context(), alice.ID, notify.ListOptions{})
		noError(t, err)
		if len(page.Items) != 1 || page.Items[0].Recipient.ID != alice.ID {
			t.Fatal("refused ownership claim changed existing receipts")
		}
		if _, err = allowed.ListNotifications(t.Context(), alice.ID, notify.ListOptions{}); !errors.Is(err, iam.ErrUserNotFound) {
			t.Fatalf("separate tenant read existing account inbox: %v", err)
		}
	})
	t.Run("AK-J34-C05_disabled_addon_has_no_inbox_or_delivery_worker", func(t *testing.T) {
		f := newFixture(t)
		if _, err := f.auth.Notifications("application"); !errors.Is(err, authkit.ErrNotificationsDisabled) {
			t.Fatalf("disabled addon published: %v", err)
		}
		f.call(t, "GET", "/me/notifications", "", nil).want(t, http.StatusNotFound, "")
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
