package securitytest

import (
	"context"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/open-rails/authkit"
	"github.com/open-rails/authkit/iam"
	"github.com/stretchr/testify/require"
)

// TestSecuritySessionEventHistory: an account's session history holds only
// its own events, pages newest first without repeats or skips (timestamp ties
// included), refuses forged cursors, and the admin sign-in route needs
// root:users:read.
func TestSecuritySessionEventHistory(t *testing.T) {
	h := newHost(t, withHTTP(generousLimits), withEngine(func(c *authkit.Config) {
		r := authkit.NewRoles()
		r.Root.Role("auditor", r.Root.Users.Read)
		c.Roles = r
	}))
	ctx := context.Background()
	a, other := h.newAccount("history"), h.newAccount("historyother")
	h.login(a)
	h.login(a)
	bad := h.post("/password/login", map[string]string{"identifier": a.email, "password": "Wrong-horse-battery-9"}, "")
	require.Equal(t, http.StatusUnauthorized, bad.status, bad.String())
	sessions, err := h.auth.Sessions(ctx, a.id)
	require.NoError(t, err)
	require.Len(t, sessions, 2)
	require.NoError(t, h.auth.RevokeSession(ctx, iam.UserActor(a.id), a.id, sessions[0].ID))
	h.login(other)

	history := func(q iam.SessionEventQuery) []iam.SessionEvent {
		t.Helper()
		var out []iam.SessionEvent
		for {
			page, err := h.auth.SessionEvents(ctx, a.id, q)
			require.NoError(t, err)
			out = append(out, page.Items...)
			if page.Next == "" {
				return out
			}
			q.Page.Cursor = page.Next
		}
	}
	all := history(iam.SessionEventQuery{})
	kinds := map[iam.SessionEventKind]int{}
	for i, e := range all {
		kinds[e.Kind]++
		require.Equal(t, issuer, e.Issuer)
		if i > 0 {
			require.False(t, e.OccurredAt.After(all[i-1].OccurredAt), "history is not newest first")
		}
	}
	require.Equal(t, map[iam.SessionEventKind]int{iam.SessionEventCreated: 2, iam.SessionEventFailed: 1, iam.SessionEventRevoked: 1}, kinds)
	require.Equal(t, iam.SessionEventRevoked, all[0].Kind)
	require.Equal(t, sessions[0].ID, all[0].SessionID)
	failed := history(iam.SessionEventQuery{Kinds: []iam.SessionEventKind{iam.SessionEventFailed}})
	require.Len(t, failed, 1)
	require.NotEmpty(t, failed[0].Reason)
	require.NotEmpty(t, failed[0].IP)

	theirs, err := h.auth.SessionEvents(ctx, other.id, iam.SessionEventQuery{})
	require.NoError(t, err)
	require.Len(t, theirs.Items, 1)
	for _, e := range all {
		require.NotEqual(t, theirs.Items[0].SessionID, e.SessionID, "another account's session is in the history")
	}

	t.Run("paging repeats and skips nothing, ties included", func(t *testing.T) {
		tie := time.Now().Add(time.Hour).UTC().Truncate(time.Microsecond)
		for i := range 3 {
			_, err := h.pool.Exec(ctx, `INSERT INTO session_events (occurred_at, issuer, user_id, session_id, event) VALUES ($1,$2,$3,$4,'session_created')`,
				tie, issuer, a.id, fmt.Sprintf("tie-%d", i))
			require.NoError(t, err)
		}
		whole := history(iam.SessionEventQuery{})
		require.Len(t, whole, len(all)+3)
		for _, limit := range []int{1, 2, 3} {
			require.Equal(t, whole, history(iam.SessionEventQuery{Page: iam.PageRequest{Limit: limit}}), "limit %d", limit)
		}
	})

	t.Run("forged cursors and ids", func(t *testing.T) {
		for _, cursor := range []string{"garbage", base64.RawURLEncoding.EncodeToString([]byte(`["yesterday","1"]`)), base64.RawURLEncoding.EncodeToString([]byte(`["2026-01-01T00:00:00Z"]`))} {
			_, err := h.auth.SessionEvents(ctx, a.id, iam.SessionEventQuery{Page: iam.PageRequest{Cursor: cursor}})
			e, ok := iam.AsError(err)
			require.True(t, ok, "cursor %q: %v", cursor, err)
			require.Equal(t, "invalid_request", e.Code())
		}
		_, err := h.auth.SessionEvents(ctx, "not-a-uuid", iam.SessionEventQuery{})
		require.ErrorIs(t, err, iam.ErrUserNotFound)
	})

	t.Run("admin sign-in route", func(t *testing.T) {
		auditor := h.newAccount("auditor")
		h.grant(iam.RootGroup(), auditor, "auditor")
		token := h.login(auditor).AccessToken
		var seen []iam.SessionEvent
		cursor := ""
		for {
			resp := h.get("/admin/users/"+a.id+"/signins?limit=2&cursor="+url.QueryEscape(cursor), token)
			require.Equal(t, http.StatusOK, resp.status, resp.String())
			var page struct {
				Data []iam.SessionEvent `json:"data"`
				Next string             `json:"next_cursor"`
			}
			resp.json(t, &page)
			require.LessOrEqual(t, len(page.Data), 2)
			seen = append(seen, page.Data...)
			if page.Next == "" {
				break
			}
			cursor = page.Next
		}
		require.Len(t, seen, 6, "two sign-ins, one failure and three tied sign-ins")
		for _, e := range seen {
			require.Contains(t, []iam.SessionEventKind{iam.SessionEventCreated, iam.SessionEventFailed}, e.Kind)
		}
		resp := h.get("/admin/users/"+a.id+"/signins", h.login(other).AccessToken)
		require.Equal(t, http.StatusForbidden, resp.status, resp.String())
	})
}
