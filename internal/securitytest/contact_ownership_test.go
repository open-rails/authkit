package securitytest

import (
	"context"
	"net/http"
	"sync"
	"testing"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/stretchr/testify/require"

	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/internal/httpapi"
)

// contactKind is one kind of contact an account is reached at: its field on
// PUT /me/<kind>, its column, the in-use code and a fresh address.
type contactKind struct {
	name, field, column, inUse string
	fresh                      func() string
	holder                     func(*iam.User) *string
}

var contactKinds = []contactKind{
	{name: "email", field: "email", column: "email", inUse: "email_in_use",
		fresh:  func() string { return unique("owned") + "@security.test" },
		holder: func(u *iam.User) *string { return u.Email }},
	{name: "phone", field: "phone_number", column: "phone_number", inUse: "phone_in_use",
		fresh:  func() string { return "+1415555" + uniqueDigits(4) },
		holder: func(u *iam.User) *string { return u.Phone }},
}

// TestSecurityContactOwnership (#449 q1, owner ruling 2026-10-11): an email
// or phone is tied to one account at a time, by a unique constraint.
// Proving a contact an account holds signs into that account, never into a
// second one; registering with it is refused. Changing to another contact
// releases the old one at once, and another account may then sign up with
// it or move to it by proving it. Of two accounts moving to one contact at
// once, exactly one gets it.
func TestSecurityContactOwnership(t *testing.T) {
	ctx := context.Background()
	h := newNetworkHost(t)
	for _, k := range contactKinds {
		t.Run(k.name, func(t *testing.T) {
			signUp := func(contact, address string) httpapi.AuthResult {
				t.Helper()
				res := authResult(t, h.codeSignIn(contact, address, termsV1, privacyV1))
				require.Equal(t, httpapi.AuthComplete, res.Status)
				require.True(t, res.Created)
				return res
			}
			// move changes the account behind token to contact, proving it.
			move := func(token, contact string) response {
				t.Helper()
				resp := h.do(request{method: http.MethodPut, path: "/me/" + k.name, body: map[string]string{k.field: contact}, token: token})
				if resp.status != http.StatusAccepted {
					return resp
				}
				return h.post("/verify/confirm", map[string]string{"identifier": contact, "code": h.lastCode(contact)}, token)
			}
			holderOf := func(contact string) string {
				t.Helper()
				ref := iam.UserByEmail(contact)
				if k.name == "phone" {
					ref = iam.UserByPhone(contact)
				}
				u, err := h.auth.User(ctx, ref)
				if err != nil {
					return ""
				}
				return u.ID
			}

			x, y := k.fresh(), k.fresh()
			a := signUp(x, "203.0.113.70")
			b := signUp(y, "203.0.113.71")
			bToken := b.TokenSet.AccessToken

			// Held: another account can neither move to it nor register with it,
			// and proving it signs into its holder.
			require.Equal(t, k.inUse, move(bToken, x).errorCode())
			reg := h.post("/register", map[string]any{"identifier": x, "username": unique("ownreg"), "password": password,
				"agreements": []iam.AgreementRef{termsV1, privacyV1}}, "")
			require.Equal(t, k.inUse, reg.errorCode(), reg.String())
			again := authResult(t, h.codeSignIn(x, "203.0.113.70"))
			require.Equal(t, a.User.ID, again.User.ID)
			require.False(t, again.Created)

			// A moves to x2: x is released at once, and B moves to it.
			x2 := k.fresh()
			resp := move(again.TokenSet.AccessToken, x2)
			require.Equal(t, http.StatusNoContent, resp.status, resp.String())
			require.Equal(t, a.User.ID, holderOf(x2))
			require.Empty(t, holderOf(x), "the old contact is free")
			resp = move(bToken, x)
			require.Equal(t, http.StatusNoContent, resp.status, resp.String())
			require.Equal(t, b.User.ID, holderOf(x))
			byX := authResult(t, h.codeSignIn(x, "203.0.113.71"))
			require.Equal(t, b.User.ID, byX.User.ID, "x now signs into B")
			require.Equal(t, x, *k.holder(byX.User))

			// B's old contact y is free too: a new person signs up with it.
			c := signUp(y, "203.0.113.72")
			require.NotEqual(t, b.User.ID, c.User.ID)

			// Two accounts moving to one free contact at once: exactly one gets it.
			z := k.fresh()
			racers := []httpapi.AuthResult{signUp(k.fresh(), "203.0.113.73"), signUp(k.fresh(), "203.0.113.74")}
			for _, r := range racers {
				resp := h.do(request{method: http.MethodPut, path: "/me/" + k.name, body: map[string]string{k.field: z}, token: r.TokenSet.AccessToken})
				require.Equal(t, http.StatusAccepted, resp.status, resp.String())
			}
			codes := h.mail.Messages(iam.MessageVerification, z)
			require.Len(t, codes, 2)
			results := make([]response, len(racers))
			var wg sync.WaitGroup
			for i, r := range racers {
				wg.Go(func() {
					results[i] = h.post("/verify/confirm", map[string]string{"identifier": z, "code": codes[i].Code}, r.TokenSet.AccessToken)
				})
			}
			wg.Wait()
			won := 0
			for _, r := range results {
				switch {
				case r.status == http.StatusNoContent:
					won++
				default:
					require.Equal(t, k.inUse, r.errorCode(), r.String())
				}
			}
			require.Equal(t, 1, won)
			var holders int
			require.NoError(t, h.pool.QueryRow(ctx, `SELECT count(*) FROM profiles.users WHERE `+k.column+` = $1`, z).Scan(&holders))
			require.Equal(t, 1, holders)

			// The constraint holds whatever code writes it.
			_, err := h.pool.Exec(ctx, `UPDATE profiles.users SET `+k.column+` = $1 WHERE id = $2`, z, c.User.ID)
			var pgErr *pgconn.PgError
			require.ErrorAs(t, err, &pgErr)
			require.Equal(t, "23505", pgErr.Code, "unique_violation")
		})
	}
}
