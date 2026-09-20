package embedded

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	authkit "github.com/open-rails/authkit"
	"github.com/open-rails/authkit/internal/testdb"
	"github.com/stretchr/testify/require"
)

// Two sites with separate logins share one account store; a third site shares
// the store but is outside the account issuer set. Real engines, real PG.
func TestErasureHandoffAcrossSites(t *testing.T) {
	pool := testdb.Pool(t)
	ctx := context.Background()
	suffix := fmt.Sprint(time.Now().UnixNano())
	issuerA := "https://erasure-a-" + suffix + ".test"
	issuerB := "https://erasure-b-" + suffix + ".test"
	issuerC := "https://erasure-c-" + suffix + ".test"
	site := func(issuer string, account ...string) *Client {
		return mustNewWithKeys(t, Config{Token: TokenConfig{Issuer: issuer, AccountIssuers: account}}, Keyset{}, Deps{Postgres: pool})
	}
	siteA, siteB, siteC := site(issuerA, issuerB), site(issuerB, issuerA), site(issuerC)

	var created []string
	t.Cleanup(func() {
		for _, id := range created {
			_, _ = pool.Exec(context.Background(), `DELETE FROM users WHERE id=$1::uuid`, id)
			_, _ = pool.Exec(context.Background(), `DELETE FROM account_erasure_obligations WHERE user_id=$1::uuid`, id)
		}
	})
	mk := func(tag string) *User {
		t.Helper()
		u, err := siteA.CreateUser(ctx, fmt.Sprintf("%s-%s@example.test", tag, suffix), fmt.Sprintf("er_%s_%s", tag, suffix[len(suffix)-8:]))
		require.NoError(t, err)
		created = append(created, u.ID)
		return u
	}
	ids := func(page []authkit.ErasureObligation) []string {
		out := make([]string, len(page))
		for i, o := range page {
			out[i] = o.UserID
		}
		return out
	}
	listAll := func(c *Client, issuer string, limit int) []authkit.ErasureObligation {
		t.Helper()
		var all []authkit.ErasureObligation
		next := ""
		for {
			page, cursor, err := c.ListErasureObligations(ctx, issuer, next, limit)
			require.NoError(t, err)
			all = append(all, page...)
			if cursor == "" {
				return all
			}
			require.Len(t, page, limit, "a continuation is only offered on a full page")
			next = cursor
		}
	}
	backlog := func(issuer string) authkit.ErasureSiteBacklog {
		t.Helper()
		rows, err := siteA.ErasureBacklog(ctx)
		require.NoError(t, err)
		for _, r := range rows {
			if r.Site == issuer {
				return r
			}
		}
		return authkit.ErasureSiteBacklog{Site: issuer}
	}
	userExists := func(id string) bool {
		var n int
		require.NoError(t, pool.QueryRow(ctx, `SELECT count(*) FROM users WHERE id=$1::uuid`, id).Scan(&n))
		return n == 1
	}
	obligationExists := func(id string) bool {
		var n int
		require.NoError(t, pool.QueryRow(ctx, `SELECT count(*) FROM account_erasure_obligations WHERE user_id=$1::uuid`, id).Scan(&n))
		return n == 1
	}
	purgeable := func(c *Client) map[string]bool {
		t.Helper()
		got, err := c.ListUsersDeletedBefore(ctx, time.Now(), 10000)
		require.NoError(t, err)
		set := map[string]bool{}
		for _, id := range got {
			set[id] = true
		}
		return set
	}

	var fleet []*User
	for i := range 7 {
		fleet = append(fleet, mk(fmt.Sprintf("fleet%d", i)))
	}

	t.Run("deletion raises one obligation per account issuer", func(t *testing.T) {
		require.NoError(t, siteA.SoftDeleteUser(ctx, fleet[0].ID))
		for _, issuer := range []string{issuerA, issuerB} {
			page := listAll(siteA, issuer, 10)
			require.Equal(t, []string{fleet[0].ID}, ids(page))
			require.Equal(t, *fleet[0].Email, page[0].Email)
			require.Equal(t, *fleet[0].Username, page[0].Username)
			require.Nil(t, page[0].PurgedAt, "identity still retained")
			require.Equal(t, 1, backlog(issuer).Pending)
			require.WithinDuration(t, time.Now(), backlog(issuer).Oldest, time.Minute)
		}
		require.Empty(t, listAll(siteC, issuerC, 10), "a site outside the account issuer set is not required")
	})

	t.Run("listing pages the keyset past a small limit", func(t *testing.T) {
		for _, u := range fleet[1:] {
			require.NoError(t, siteA.SoftDeleteUser(ctx, u.ID))
		}
		all := listAll(siteB, issuerB, 3)
		require.Len(t, all, 7)
		for i := 1; i < len(all); i++ {
			prev, cur := all[i-1], all[i]
			require.False(t, cur.CreatedAt.Before(prev.CreatedAt), "oldest first")
			require.True(t, cur.CreatedAt.After(prev.CreatedAt) || cur.UserID > prev.UserID, "stable (created_at, user_id) keyset")
		}
		require.ElementsMatch(t, ids(all), func() []string {
			out := []string{}
			for _, u := range fleet {
				out = append(out, u.ID)
			}
			return out
		}())
		for _, bad := range []string{"not-a-cursor", "2026-09-17T00:00:00Z/not-a-uuid", "nope/" + fleet[0].ID} {
			_, _, err := siteB.ListErasureObligations(ctx, issuerB, bad, 3)
			require.ErrorContains(t, err, "malformed erasure cursor", bad)
		}
		_, _, err := siteB.ListErasureObligations(ctx, " ", "", 3)
		require.ErrorContains(t, err, "site is required")
	})

	t.Run("purge retains the identity until every issuer acknowledged", func(t *testing.T) {
		var accepted []string
		res, err := authkit.AcceptErasureObligations(ctx, siteA, issuerA, 3, func(_ context.Context, o authkit.ErasureObligation) error {
			accepted = append(accepted, o.UserID)
			return nil
		})
		require.NoError(t, err)
		require.Equal(t, authkit.ErasureAcceptance{Acknowledged: 7}, res)
		require.Len(t, accepted, 7)
		require.Equal(t, 0, backlog(issuerA).Pending)
		require.Equal(t, 7, backlog(issuerB).Pending)

		set := purgeable(siteA)
		for _, u := range fleet {
			require.False(t, set[u.ID], "site B has not acknowledged: %s must not be purge-ready", u.ID)
			require.True(t, userExists(u.ID))
		}
	})

	t.Run("a crash before acknowledgement leaves the obligation and resumes", func(t *testing.T) {
		first, _, err := siteB.ListErasureObligations(ctx, issuerB, "", 2)
		require.NoError(t, err)
		require.Len(t, first, 2) // recorded locally, then crashed before AcknowledgeErasure
		again, _, err := siteB.ListErasureObligations(ctx, issuerB, "", 2)
		require.NoError(t, err)
		require.Equal(t, ids(first), ids(again))
		require.Equal(t, 7, backlog(issuerB).Pending)

		res, err := authkit.AcceptErasureObligations(ctx, siteB, issuerB, 2, func(_ context.Context, o authkit.ErasureObligation) error {
			if o.UserID == first[0].UserID {
				return errors.New("local ledger unavailable")
			}
			return nil
		})
		require.ErrorContains(t, err, "local ledger unavailable")
		require.Equal(t, authkit.ErasureAcceptance{Acknowledged: 6, Failed: 1}, res, "one failure never blocks the later pages")
		require.Equal(t, []string{first[0].UserID}, ids(listAll(siteB, issuerB, 10)))
		require.False(t, purgeable(siteA)[first[0].UserID])
	})

	t.Run("the offline site acknowledges later and purge on the other site completes", func(t *testing.T) {
		res, err := authkit.AcceptErasureObligations(ctx, siteB, issuerB, 2, func(context.Context, authkit.ErasureObligation) error { return nil })
		require.NoError(t, err)
		require.Equal(t, authkit.ErasureAcceptance{Acknowledged: 1}, res)

		set := purgeable(siteA)
		for _, u := range fleet {
			require.True(t, set[u.ID], "both issuers acknowledged: %s is purge-ready", u.ID)
		}
		results, err := siteA.HardDeleteUsers(ctx, ids(listAll(siteC, issuerC, 10))) // C sees nothing
		require.NoError(t, err)
		require.Empty(t, results)
		var purge []string
		for _, u := range fleet {
			purge = append(purge, u.ID)
		}
		results, err = siteA.HardDeleteUsers(ctx, purge)
		require.NoError(t, err)
		for _, r := range results {
			require.NoError(t, r.Err)
		}
		for _, u := range fleet {
			require.False(t, userExists(u.ID))
			require.False(t, obligationExists(u.ID), "closed once purged and fully acknowledged")
		}
		require.Equal(t, 0, backlog(issuerA).Pending)
		require.Equal(t, 0, backlog(issuerB).Pending)
		require.Empty(t, purgeable(siteB))
	})

	t.Run("a direct hard delete keeps the obligation and identifiers until acknowledged", func(t *testing.T) {
		soft, live := mk("directsoft"), mk("directlive")
		require.NoError(t, siteB.SoftDeleteUser(ctx, soft.ID))
		results, err := siteA.HardDeleteUsers(ctx, []string{soft.ID, live.ID})
		require.NoError(t, err)
		for _, r := range results {
			require.NoError(t, r.Err)
		}
		for _, u := range []*User{soft, live} {
			require.False(t, userExists(u.ID))
			for _, c := range []struct {
				client *Client
				issuer string
			}{{siteA, issuerA}, {siteB, issuerB}} {
				var got *authkit.ErasureObligation
				for _, o := range listAll(c.client, c.issuer, 10) {
					if o.UserID == u.ID {
						o := o
						got = &o
					}
				}
				require.NotNil(t, got, "%s still owes %s after the identity is gone", c.issuer, u.ID)
				require.Equal(t, *u.Email, got.Email)
				require.Equal(t, *u.Username, got.Username)
				require.NotNil(t, got.PurgedAt)
			}
			require.NoError(t, siteA.AcknowledgeErasure(ctx, issuerA, u.ID))
			require.True(t, obligationExists(u.ID), "site B still pending")
			require.NoError(t, siteB.AcknowledgeErasure(ctx, issuerB, u.ID))
			require.False(t, obligationExists(u.ID))
		}
	})

	t.Run("a site outside the account issuer set is not required and may still purge", func(t *testing.T) {
		u := mk("solo")
		require.NoError(t, siteC.SoftDeleteUser(ctx, u.ID))
		require.Empty(t, listAll(siteA, issuerA, 10))
		require.Empty(t, listAll(siteB, issuerB, 10))
		require.Equal(t, []string{u.ID}, ids(listAll(siteC, issuerC, 10)))
		require.False(t, purgeable(siteA)[u.ID])
		require.NoError(t, siteC.AcknowledgeErasure(ctx, issuerC, u.ID))
		require.True(t, purgeable(siteA)[u.ID], "only the issuers configured at deletion are required")
		results, err := siteA.HardDeleteUsers(ctx, []string{u.ID})
		require.NoError(t, err)
		require.NoError(t, results[0].Err)
		require.False(t, userExists(u.ID))
		// The purging host's own account issuers are always required: A's
		// configuration names A and B, so both now owe this obligation.
		require.Equal(t, []string{u.ID}, ids(listAll(siteA, issuerA, 10)))
		require.Equal(t, []string{u.ID}, ids(listAll(siteB, issuerB, 10)))
		require.NoError(t, siteA.AcknowledgeErasure(ctx, issuerA, u.ID))
		require.NoError(t, siteB.AcknowledgeErasure(ctx, issuerB, u.ID))
		require.False(t, obligationExists(u.ID))
	})

	t.Run("concurrent final acknowledgements close the obligation exactly once", func(t *testing.T) {
		for i := range 5 {
			u := mk(fmt.Sprintf("race%d", i))
			require.NoError(t, siteA.SoftDeleteUser(ctx, u.ID))
			results, err := siteA.HardDeleteUsers(ctx, []string{u.ID})
			require.NoError(t, err)
			require.NoError(t, results[0].Err)
			var wg sync.WaitGroup
			errs := make(chan error, 2)
			for _, s := range []struct {
				client *Client
				issuer string
			}{{siteA, issuerA}, {siteB, issuerB}} {
				wg.Add(1)
				go func() {
					defer wg.Done()
					errs <- s.client.AcknowledgeErasure(ctx, s.issuer, u.ID)
				}()
			}
			wg.Wait()
			close(errs)
			for err := range errs {
				require.NoError(t, err)
			}
			require.False(t, obligationExists(u.ID))
		}
	})

	t.Run("acknowledging is idempotent", func(t *testing.T) {
		require.NoError(t, siteA.AcknowledgeErasure(ctx, issuerA, fleet[0].ID), "closed obligation")
		require.NoError(t, siteA.AcknowledgeErasure(ctx, issuerA, "00000000-0000-0000-0000-000000000000"), "unknown user")
		require.ErrorContains(t, siteA.AcknowledgeErasure(ctx, "", fleet[0].ID), "site is required")
	})
}
