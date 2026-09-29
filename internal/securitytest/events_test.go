package securitytest

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/open-rails/authkit"
	"github.com/open-rails/authkit/iam"
	"github.com/stretchr/testify/require"
)

// eventLog is a host's Deps.OnEvent. The first delivery of a kind in
// failFirst fails, as a host store outage would.
type eventLog struct {
	mu        sync.Mutex
	failFirst map[iam.EventKind]bool
	calls     map[string]int
	delivered []iam.Event
}

func newEventLog(failFirst ...iam.EventKind) *eventLog {
	l := &eventLog{failFirst: map[iam.EventKind]bool{}, calls: map[string]int{}}
	for _, k := range failFirst {
		l.failFirst[k] = true
	}
	return l
}

func (l *eventLog) hook(_ context.Context, e iam.Event) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.calls[e.ID]++
	if l.failFirst[e.Kind] && l.calls[e.ID] == 1 {
		return errors.New("host event store unavailable")
	}
	l.delivered = append(l.delivered, e)
	return nil
}

func withEvents(l *eventLog) hostOption {
	return func(c *hostConfig) { c.deps.OnEvent = l.hook }
}

// withRBACNoMFA is withRBAC without second factors in the way.
func withRBACNoMFA(c *authkit.Config) {
	withRBAC(c)
	c.TwoFactor.Mode = iam.TwoFactorDisabled
}

// drained waits until every recorded event is delivered and its job done,
// then returns the deliveries in order.
func (l *eventLog) drained(h *host) []iam.Event {
	h.t.Helper()
	require.Eventually(h.t, func() bool {
		var pending int
		err := h.pool.QueryRow(context.Background(), `SELECT (SELECT count(*) FROM account_events)
 + (SELECT count(*) FROM public.river_job WHERE kind='authkit_account_event' AND state NOT IN ('completed','cancelled','discarded'))`).Scan(&pending)
		return err == nil && pending == 0
	}, time.Minute, 50*time.Millisecond, "events stay undelivered")
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([]iam.Event(nil), l.delivered...)
}

// await waits for a delivery of kind about userID.
func (l *eventLog) await(t *testing.T, kind iam.EventKind, userID string) {
	t.Helper()
	require.Eventually(t, func() bool {
		l.mu.Lock()
		defer l.mu.Unlock()
		for _, e := range l.delivered {
			if e.Kind == kind && e.UserID == userID {
				return true
			}
		}
		return false
	}, time.Minute, 50*time.Millisecond, "no %s event", kind)
}

// proveOwnEmail verifies a registrant's address from its own session, which
// keeps its password.
func (h *host) proveOwnEmail(email string, own tokens) {
	h.t.Helper()
	require.Less(h.t, h.post("/verify/request", map[string]string{"identifier": email}, "").status, 300)
	resp := h.post("/verify/confirm", map[string]string{"identifier": email, "code": h.verificationCode(email)}, own.AccessToken)
	require.Equal(h.t, http.StatusOK, resp.status, resp.String())
}

// sig is what an event says, without its id and time.
func sig(e iam.Event) string {
	return fmt.Sprintf("%s user=%s group=%s persona=%s app=%s by=%s:%s %q->%q", e.Kind, e.UserID, e.GroupID, e.Persona, e.ApplicationID, e.ActorKind, e.ActorID, e.Previous, e.Current)
}

// TestSecurityEventsRecordOnlyCommittedChanges: a host's audit trail (ban
// history, membership mirrors) sees every committed change exactly once,
// whichever surface made it, and never a refused or rolled-back one. A failing
// hook is retried with the same event ID and holds back that user's later
// events.
func TestSecurityEventsRecordOnlyCommittedChanges(t *testing.T) {
	events := newEventLog(iam.EventUserBanned)
	h := newHost(t, withHTTP(generousLimits), withEngine(withRBACNoMFA), withEvents(events))
	ctx := context.Background()
	require.NoError(t, h.auth.Start(ctx))
	system := iam.SystemActor()
	root := iam.RootGroup()
	rootGroup, err := h.auth.Group(ctx, root)
	require.NoError(t, err)
	var want []string
	expect := func(e iam.Event) { want = append(want, sig(e)) }
	bySystem := func(e iam.Event) iam.Event { e.ActorKind = iam.ActorSystem; return e }
	byUser := func(id string, e iam.Event) iam.Event { e.ActorKind, e.ActorID = iam.ActorUser, id; return e }

	staff := h.newAccount("staff")
	expect(bySystem(iam.Event{Kind: iam.EventUserRegistered, UserID: staff.id}))
	h.grant(root, staff, "superadmin")
	expect(bySystem(iam.Event{Kind: iam.EventRoleGranted, UserID: staff.id, GroupID: rootGroup.ID, Persona: iam.RootPersona, Current: "superadmin"}))
	staffToken := h.login(staff).AccessToken

	aliceEmail := unique("alice") + "@security.test"
	aliceTokens := h.register(aliceEmail)
	alice := account{id: h.userID(aliceEmail), email: aliceEmail}
	expect(byUser(alice.id, iam.Event{Kind: iam.EventUserRegistered, UserID: alice.id}))
	h.proveOwnEmail(aliceEmail, aliceTokens)

	t.Run("refused bans record nothing", func(t *testing.T) {
		resp := h.post("/admin/users/"+staff.id+"/ban", map[string]string{"until": "infinite"}, aliceTokens.AccessToken)
		require.Equal(t, http.StatusForbidden, resp.status, resp.String())
		resp = h.post("/admin/users/"+staff.id+"/ban", map[string]string{"until": "infinite"}, staffToken)
		require.GreaterOrEqual(t, resp.status, 400, "nobody bans themselves: %s", resp.String())
	})

	until := time.Now().Add(time.Hour).UTC().Truncate(time.Second)
	resp := h.post("/admin/users/"+alice.id+"/ban", map[string]string{"reason": "spam", "until": until.Format(time.RFC3339)}, staffToken)
	require.Equal(t, http.StatusNoContent, resp.status, resp.String())
	expect(byUser(staff.id, iam.Event{Kind: iam.EventUserBanned, UserID: alice.id}))
	resp = h.post("/admin/users/"+alice.id+"/ban", map[string]any{"until": "infinite", "keep_existing": true}, staffToken)
	require.Equal(t, http.StatusNoContent, resp.status, "a ban in force is kept: %s", resp.String())
	for range 2 { // the second lift finds no ban
		resp = h.post("/admin/users/"+alice.id+"/unban", nil, staffToken)
		require.Equal(t, http.StatusNoContent, resp.status, resp.String())
	}
	expect(byUser(staff.id, iam.Event{Kind: iam.EventUserUnbanned, UserID: alice.id}))

	aliceToken := h.login(alice).AccessToken
	newEmail := unique("alicenew") + "@security.test"
	resp = h.post("/verify/request", map[string]string{"identifier": newEmail, "password": password}, aliceToken)
	require.Equal(t, http.StatusAccepted, resp.status, resp.String())
	resp = h.post("/verify/confirm", map[string]string{"identifier": newEmail, "code": h.verificationCode(newEmail)}, aliceToken)
	require.Equal(t, http.StatusNoContent, resp.status, resp.String())
	expect(byUser(alice.id, iam.Event{Kind: iam.EventUserEmailChanged, UserID: alice.id, Previous: aliceEmail, Current: newEmail}))

	username, phone := unique("alicerenamed"), "+14155550142"
	before, err := h.auth.User(ctx, iam.UserByID(alice.id))
	require.NoError(t, err)
	invalid := "not-an-email"
	_, err = h.auth.UpdateUser(ctx, system, alice.id, iam.UserUpdate{Username: &username, Email: &invalid})
	require.Error(t, err, "a rename in a refused update rolls back")
	_, err = h.auth.UpdateUser(ctx, system, alice.id, iam.UserUpdate{Username: &username, Phone: &phone})
	require.NoError(t, err)
	expect(bySystem(iam.Event{Kind: iam.EventUserPhoneChanged, UserID: alice.id, Current: phone}))
	expect(bySystem(iam.Event{Kind: iam.EventUserUsernameChanged, UserID: alice.id, Previous: before.Username, Current: username}))

	bob := h.newAccount("bob")
	expect(bySystem(iam.Event{Kind: iam.EventUserRegistered, UserID: bob.id}))
	bobToken := h.login(bob).AccessToken
	bobSubject := iam.UserSubject(bob.id)
	group, err := h.auth.CreateGroup(ctx, iam.NewGroup{Persona: orgPersona, Owner: &bobSubject})
	require.NoError(t, err)
	org := iam.GroupByID(group.ID)
	expect(bySystem(iam.Event{Kind: iam.EventGroupCreated, GroupID: group.ID, Persona: orgPersona}))
	expect(bySystem(iam.Event{Kind: iam.EventRoleGranted, UserID: bob.id, GroupID: group.ID, Persona: orgPersona, Current: "owner"}))

	resp = h.do(request{method: http.MethodPut, path: "/groups/" + group.ID + "/members/" + alice.id + "/roles/member", token: bobToken})
	require.Less(t, resp.status, 300, resp.String())
	expect(byUser(bob.id, iam.Event{Kind: iam.EventRoleGranted, UserID: alice.id, GroupID: group.ID, Persona: orgPersona, Current: "member"}))
	for range 2 { // the second assignment changes nothing
		res, err := h.auth.AssignGroupRoles(ctx, iam.UserActor(bob.id), org, []iam.Subject{iam.UserSubject(alice.id)}, h.role(orgPersona, "manager"))
		require.NoError(t, err)
		require.NoError(t, res[0].Err)
	}
	expect(byUser(bob.id, iam.Event{Kind: iam.EventRoleChanged, UserID: alice.id, GroupID: group.ID, Persona: orgPersona, Previous: "member", Current: "manager"}))
	t.Run("refused assignments record nothing", func(t *testing.T) {
		res, err := h.auth.AssignGroupRoles(ctx, iam.UserActor(alice.id), org, []iam.Subject{iam.UserSubject(alice.id), iam.UserSubject(staff.id)}, orgPersona.OwnerRole())
		require.NoError(t, err)
		require.Error(t, res[0].Err, "a manager cannot make itself owner")
		require.Error(t, res[1].Err, "nor anyone else")
		res, err = h.auth.AssignGroupRoles(ctx, iam.UserActor(bob.id), org, []iam.Subject{iam.UserSubject("0198a0f0-0000-7000-8000-000000000000")}, h.role(orgPersona, "member"))
		require.NoError(t, err)
		require.ErrorIs(t, res[0].Err, iam.ErrUserNotFound)
	})
	res, err := h.auth.UnassignGroupRoles(ctx, iam.UserActor(bob.id), org, []iam.Subject{iam.UserSubject(alice.id)}, h.role(orgPersona, "manager"))
	require.NoError(t, err)
	require.NoError(t, res[0].Err)
	expect(byUser(bob.id, iam.Event{Kind: iam.EventRoleRevoked, UserID: alice.id, GroupID: group.ID, Persona: orgPersona, Previous: "manager"}))

	grantRole(t, h.auth, root, iam.UserSubject(alice.id), "moderator")
	revokeRole(t, h.auth, root, iam.UserSubject(alice.id), "moderator")
	expect(bySystem(iam.Event{Kind: iam.EventRoleGranted, UserID: alice.id, GroupID: rootGroup.ID, Persona: iam.RootPersona, Current: "moderator"}))
	expect(bySystem(iam.Event{Kind: iam.EventRoleRevoked, UserID: alice.id, GroupID: rootGroup.ID, Persona: iam.RootPersona, Previous: "moderator"}))

	require.NoError(t, h.auth.DeleteGroup(ctx, org))
	require.NoError(t, h.auth.DeleteGroup(ctx, org), "deleting again records nothing")
	expect(bySystem(iam.Event{Kind: iam.EventGroupDeleted, GroupID: group.ID, Persona: orgPersona}))
	require.NoError(t, h.auth.PurgeGroup(ctx, org))
	expect(bySystem(iam.Event{Kind: iam.EventGroupPurged, GroupID: group.ID, Persona: orgPersona}))

	resp = h.do(request{method: http.MethodDelete, path: "/admin/users/" + alice.id, token: staffToken})
	require.Equal(t, http.StatusNoContent, resp.status, resp.String())
	expect(byUser(staff.id, iam.Event{Kind: iam.EventUserDeleted, UserID: alice.id}))
	resp = h.post("/admin/users/"+alice.id+"/restore", nil, staffToken)
	require.Equal(t, http.StatusNoContent, resp.status, resp.String())
	expect(byUser(staff.id, iam.Event{Kind: iam.EventUserRestored, UserID: alice.id}))

	t.Run("a rolled-back manifest records nothing", func(t *testing.T) {
		_, err := h.auth.ApplyBootstrapManifest(ctx, iam.BootstrapManifest{Users: []iam.BootstrapManifestUser{
			{Username: unique("seeded"), Email: unique("seeded") + "@security.test"},
			{Username: bob.username, Email: unique("squat") + "@security.test"},
		}}, iam.BootstrapOptions{})
		require.Error(t, err)
	})

	purged, err := h.auth.PurgeUsers(ctx, []string{alice.id})
	require.NoError(t, err)
	require.NoError(t, purged[0].Err)
	expect(bySystem(iam.Event{Kind: iam.EventUserDeleted, UserID: alice.id}))
	expect(iam.Event{Kind: iam.EventUserPurged, UserID: alice.id})
	events.await(t, iam.EventUserPurged, alice.id)

	delivered := events.drained(h)
	got := make([]string, len(delivered))
	for i, e := range delivered {
		got[i] = sig(e)
	}
	require.ElementsMatch(t, want, got, "each committed change exactly once, nothing else")

	var aliceWant, aliceGot []string
	for _, s := range want {
		if strings.Contains(s, "user="+alice.id+" ") {
			aliceWant = append(aliceWant, s)
		}
	}
	for _, s := range got {
		if strings.Contains(s, "user="+alice.id+" ") {
			aliceGot = append(aliceGot, s)
		}
	}
	require.Equal(t, aliceWant, aliceGot, "one user's events arrive in commit order, the failed ban first")

	ids := map[string]bool{}
	for _, e := range delivered {
		require.False(t, ids[e.ID], "event %s delivered twice", e.ID)
		ids[e.ID] = true
		require.False(t, e.OccurredAt.IsZero())
		if e.Kind == iam.EventUserBanned {
			require.Equal(t, "spam", e.Reason)
			require.NotNil(t, e.Until)
			require.True(t, until.Equal(*e.Until), "ban until %v, want %v", e.Until, until)
			events.mu.Lock()
			require.Equal(t, 2, events.calls[e.ID], "the failed delivery was retried with the same event ID")
			events.mu.Unlock()
		}
	}
}

// TestSecurityEventsCarryNoSecrets: events name what changed, never a
// password, hash, token or code, in the stored outbox or in the delivered
// event.
func TestSecurityEventsCarryNoSecrets(t *testing.T) {
	events := newEventLog()
	h := newHost(t, withHTTP(generousLimits), withEngine(withRBACNoMFA), withEvents(events))
	ctx := context.Background()
	secrets := []string{password, "argon2"}

	email := unique("secret") + "@security.test"
	registered := h.register(email)
	secrets = append(secrets, registered.AccessToken, registered.RefreshToken)
	user := account{id: h.userID(email), email: email}
	h.proveOwnEmail(email, registered)
	session := h.login(user)
	secrets = append(secrets, session.AccessToken, session.RefreshToken)

	newEmail := unique("secretnew") + "@security.test"
	resp := h.post("/verify/request", map[string]string{"identifier": newEmail, "password": password}, session.AccessToken)
	require.Equal(t, http.StatusAccepted, resp.status, resp.String())
	code := h.verificationCode(newEmail)
	secrets = append(secrets, code)
	resp = h.post("/verify/confirm", map[string]string{"identifier": newEmail, "code": code}, session.AccessToken)
	require.Equal(t, http.StatusNoContent, resp.status, resp.String())

	owner := h.newAccount("secretowner")
	org, base := h.newOrg(owner)
	link := h.issue(base+"/invites/links", h.login(owner).AccessToken, map[string]any{"role": "member"})
	secrets = append(secrets, link.Code)
	resp = h.post("/invites/redeem", map[string]string{"code": link.Code}, session.AccessToken)
	require.Less(t, resp.status, 300, resp.String())
	roles, err := h.auth.GroupRoles(ctx, org, []iam.Subject{iam.UserSubject(user.id)})
	require.NoError(t, err)
	require.Equal(t, h.role(orgPersona, "member"), roles[iam.UserSubject(user.id)])

	rows, err := h.pool.Query(ctx, `SELECT row_to_json(e)::text FROM account_events e`)
	require.NoError(t, err)
	var stored []string
	for rows.Next() {
		var row string
		require.NoError(t, rows.Scan(&row))
		stored = append(stored, row)
	}
	require.NoError(t, rows.Err())
	require.NotEmpty(t, stored, "nothing is delivered before Start")

	require.NoError(t, h.auth.Start(ctx))
	delivered := events.drained(h)
	require.Len(t, delivered, len(stored))
	for _, e := range delivered {
		raw, err := json.Marshal(e)
		require.NoError(t, err)
		stored = append(stored, string(raw))
	}
	for _, record := range stored {
		for _, secret := range secrets {
			require.NotEmpty(t, secret)
			require.NotContains(t, record, secret)
		}
	}
}
