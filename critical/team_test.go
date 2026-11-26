package critical_test

import (
	"fmt"
	"net/http"
	"net/url"
	"testing"

	"github.com/jackc/pgx/v5"

	"github.com/open-rails/authkit"
	"github.com/open-rails/authkit/authtest"
	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/internal/config"
	"github.com/open-rails/authkit/internal/httpapi"
)

// rootOwner is an account holding root's owner role, freshly signed in.
func (f *fixture) rootOwner(t *testing.T) (authtest.User, iam.TokenSet) {
	t.Helper()
	u := f.user(t)
	_, err := f.auth.SetGroupRole(t.Context(), iam.SystemIdentity(), iam.RootGroup(), iam.UserSubject(u.ID), iam.RootPersona().OwnerRole())
	noError(t, err)
	return u, f.signIn(t, u)
}

// fragmentValue is a link's fragment parameter: AuthKit's links carry their
// codes where no server sees them.
func fragmentValue(t *testing.T, link, name string) string {
	t.Helper()
	u, err := url.Parse(link)
	noError(t, err)
	q, err := url.ParseQuery(u.Fragment)
	noError(t, err)
	if q.Get(name) == "" {
		t.Fatalf("link %q carries no %s", link, name)
	}
	return q.Get(name)
}

// registerWith registers identifier with an invitation's code.
func (f *fixture) registerWith(t *testing.T, identifier, username, code string) response {
	t.Helper()
	return f.call(t, "POST", "/register", "", map[string]string{"identifier": identifier, "username": username, "password": authtest.Password, "invite_code": code})
}

// registerInvited registers identifier with an invitation's code, proves it,
// and returns the session.
func (f *fixture) registerInvited(t *testing.T, identifier, username, code string) iam.TokenSet {
	t.Helper()
	challenge := challengeOf(t, f.registerWith(t, identifier, username, code))
	return signedUp(t, f.confirmCode(t, "/verify/confirm", "", codeProof{f.out.Last(t, iam.MessageVerification, identifier), challenge}))
}

// signedUp is the session r signed a new account in with.
func signedUp(t *testing.T, r response) iam.TokenSet {
	t.Helper()
	r.want(t, http.StatusOK, "")
	var out signInResult
	decode(t, r.body, &out)
	if out.Status != "complete" || out.Tokens == nil || out.User == nil {
		t.Fatalf("invited registration did not sign in: %s", r.body)
	}
	return *out.Tokens
}

// invite creates an invitation to root with the role, by email when email is
// set, answered with status.
func (f *fixture) invite(t *testing.T, token, email string, role iam.Role, status int) iam.InvitationCreated {
	t.Helper()
	body := map[string]string{"role": role.String()}
	if email != "" {
		body["email"] = email
	}
	r := f.call(t, "POST", "/groups/root/invitations", token, body)
	r.want(t, status, "")
	var created iam.InvitationCreated
	if status == http.StatusCreated {
		decode(t, r.body, &created)
	}
	return created
}

// joinedOnly fails unless id's account holds role on root and no other role
// anywhere.
func (f *fixture) joinedOnly(t *testing.T, id string, role iam.Role) {
	t.Helper()
	page, err := f.auth.ListMemberships(t.Context(), iam.UserSubject(id), iam.PageRequest{})
	noError(t, err)
	if len(page.Items) != 1 || page.Items[0].Group.Persona != iam.RootPersona() || page.Items[0].Role != role {
		t.Fatalf("the invitee holds %+v, want only %s on root", page.Items, role)
	}
}

func TestCriticalTeam(t *testing.T) {
	t.Parallel()
	t.Run("AK-J49-C01_an_invitation_by_email_registers_the_invitee_into_its_role_and_where_email_is_unavailable_the_inviter_shares_it", func(t *testing.T) {
		f := newFixture(t)
		_, owner := f.rootOwner(t)
		const email = "teammate@example.com"
		r := f.call(t, "POST", "/groups/root/invitations", owner.AccessToken, map[string]string{"email": email, "role": f.rootReader.String()})
		r.want(t, http.StatusAccepted, "")
		if len(r.body) != 0 {
			t.Errorf("an emailed invitation answered its code to the inviter: %s", r.body)
		}
		code := fragmentValue(t, f.out.Last(t, iam.MessageInvite, email).Link, "invite_code")
		session := signedUp(t, f.registerWith(t, email, "teammate", code))
		mate, err := f.auth.User(t.Context(), iam.UserByEmail(email))
		noError(t, err)
		if role := f.rootRole(t, mate.ID); role != f.rootReader {
			t.Fatalf("the invitee holds %q on root, want %q", role, f.rootReader)
		}
		// The role is the invitee's authority from their next request on.
		f.call(t, "GET", "/admin/users", session.AccessToken, nil).want(t, http.StatusOK, "")
		var listed struct {
			Data []iam.Invitation `json:"data"`
		}
		r = f.call(t, "GET", "/groups/root/invitations", owner.AccessToken, nil)
		r.want(t, http.StatusOK, "")
		decode(t, r.body, &listed)
		if len(listed.Data) != 1 || listed.Data[0].RedeemedAt == nil || listed.Data[0].Email == nil || *listed.Data[0].Email != email {
			t.Fatalf("the accepted invitation is not listed as redeemed: %s", r.body)
		}

		// Without email the invitation is created, nothing is sent, and the
		// inviter is answered its link to share.
		g := newFixture(t, authtest.WithDeps(func(d *authkit.Deps) { d.Email = nil }))
		_, gOwner := g.rootOwner(t)
		const unsent = "unsent-teammate@example.com"
		r = g.call(t, "POST", "/groups/root/invitations", gOwner.AccessToken, map[string]string{"email": unsent, "role": g.rootReader.String()})
		r.want(t, http.StatusCreated, "")
		var created iam.InvitationCreated
		decode(t, r.body, &created)
		if created.Emailed || created.Code == "" || created.Invitation.Email == nil || *created.Invitation.Email != unsent ||
			fragmentValue(t, created.URL, "invite_code") != created.Code {
			t.Fatalf("an unsent invitation was not answered with its link: %s", r.body)
		}
		if n := len(g.out.Messages(iam.MessageInvite, unsent)); n != 0 {
			t.Fatalf("an invitation was emailed %d times without email", n)
		}
		const phone = "+12025550142"
		g.registerInvited(t, phone, "sharedinvitee", created.Code)
		shared, err := g.auth.User(t.Context(), iam.UserByPhone(phone))
		noError(t, err)
		if role := g.rootRole(t, shared.ID); role != g.rootReader {
			t.Fatalf("the shared invitation's invitee holds %q on root, want %q", role, g.rootReader)
		}
	})
	t.Run("AK-J49-C02_root_role_changes_removals_and_invitations_need_a_recent_sign_in", func(t *testing.T) {
		f := newFixture(t)
		owner, session := f.rootOwner(t)
		mate := f.user(t)
		_, err := f.auth.SetGroupRole(t.Context(), iam.SystemIdentity(), iam.RootGroup(), iam.UserSubject(mate.ID), f.rootReader)
		noError(t, err)
		member := "/groups/root/members/users/" + mate.ID
		promote := map[string]string{"role": iam.RootPersona().OwnerRole().String()}

		// A sign-in older than the recent-sign-in window changes nothing on root.
		stale := authtest.StaleSession(t, f.auth, session.AccessToken)
		f.call(t, "PUT", member, stale, promote).expect(t, http.StatusUnauthorized, "step_up_required")
		f.call(t, "DELETE", member, stale, nil).expect(t, http.StatusUnauthorized, "step_up_required")
		f.call(t, "POST", "/groups/root/invitations", stale, map[string]string{"role": f.rootReader.String()}).expect(t, http.StatusUnauthorized, "step_up_required")
		if role := f.rootRole(t, mate.ID); role != f.rootReader {
			t.Fatalf("a stale sign-in changed a root role to %q", role)
		}

		// Fresh, the owner changes the role, then removes the member.
		fresh := f.signIn(t, owner).AccessToken
		f.call(t, "PUT", member, fresh, promote).want(t, http.StatusOK, "")
		if role := f.rootRole(t, mate.ID); role != iam.RootPersona().OwnerRole() {
			t.Fatalf("the role change left %q", role)
		}
		mateSession := f.signIn(t, mate).AccessToken
		f.call(t, "GET", "/groups/root/members", mateSession, nil).want(t, http.StatusOK, "")
		f.call(t, "DELETE", member, fresh, nil).want(t, http.StatusNoContent, "")
		if role := f.rootRole(t, mate.ID); !role.IsZero() {
			t.Fatalf("the removed member still holds %q", role)
		}
		f.call(t, "GET", "/groups/root/members", mateSession, nil).want(t, http.StatusForbidden, "")

		// A revoked invitation admits nobody; revoking needs a recent sign-in too.
		r := f.call(t, "POST", "/groups/root/invitations", fresh, map[string]string{"role": f.rootReader.String()})
		r.want(t, http.StatusCreated, "")
		var link iam.InvitationCreated
		decode(t, r.body, &link)
		// Not #code=: a page's OIDC step-up return handler would take it.
		if fragmentValue(t, link.URL, "link_code") != link.Code {
			t.Fatalf("invite link %q does not carry its code as link_code", link.URL)
		}
		revoke := "/groups/root/invitations/" + link.Invitation.ID
		staleAgain := authtest.StaleSession(t, f.auth, f.signIn(t, owner).AccessToken)
		f.call(t, "DELETE", revoke, staleAgain, nil).expect(t, http.StatusUnauthorized, "step_up_required")
		f.call(t, "DELETE", revoke, fresh, nil).want(t, http.StatusNoContent, "")
		stranger := f.user(t)
		f.call(t, "POST", "/invitations/redeem", f.signIn(t, stranger).AccessToken, map[string]string{"code": link.Code}).want(t, http.StatusBadRequest, "invitation_revoked")
		if role := f.rootRole(t, stranger.ID); !role.IsZero() {
			t.Fatalf("a revoked invitation granted %q", role)
		}
	})

	t.Run("AK-J49-C03_without_email_an_invitation_registers_its_invitee_unproven_into_exactly_its_role_once", func(t *testing.T) {
		f := newFixture(t, authtest.WithDeps(func(d *authkit.Deps) { d.Email = nil }), authtest.WithConfig(func(c *authkit.Config) {
			c.Registration = iam.RegistrationModeInviteOnly
		}))
		_, owner := f.rootOwner(t)
		for _, kind := range []struct{ name, email, param string }{
			{"link", "", "link_code"},
			{"unsent", "unsent@example.com", "invite_code"},
		} {
			created := f.invite(t, owner.AccessToken, kind.email, f.rootReader, http.StatusCreated)
			code := fragmentValue(t, created.URL, kind.param)
			address := kind.email
			if address == "" {
				address = "linked@example.com"
			}
			// The code is the credential: no code is sent, and none can be.
			session := signedUp(t, f.registerWith(t, address, kind.name+"invitee", code))
			u, err := f.auth.User(t.Context(), iam.UserByEmail(address))
			noError(t, err)
			if u.EmailVerified {
				t.Fatalf("%s: an invitation that was never emailed proved %s", kind.name, address)
			}
			f.joinedOnly(t, u.ID, f.rootReader)
			f.call(t, "GET", "/admin/users", session.AccessToken, nil).want(t, http.StatusOK, "")

			// Spent, the code admits nobody else.
			second := "second-" + address
			f.registerWith(t, second, kind.name+"second", code).want(t, http.StatusNotFound, "invitation_not_found")
			f.noAccount(t, second)
		}
		if sent := f.out.Messages("", ""); len(sent) != 0 {
			t.Fatalf("a deployment without email sent %d messages", len(sent))
		}
	})
	t.Run("AK-J49-C04_an_emailed_invitation_registered_at_its_address_proves_it_without_a_second_code", func(t *testing.T) {
		f := newFixture(t)
		_, owner := f.rootOwner(t)
		const email = "proven@example.com"
		f.invite(t, owner.AccessToken, email, f.rootReader, http.StatusAccepted)
		code := fragmentValue(t, f.out.Last(t, iam.MessageInvite, email).Link, "invite_code")
		signedUp(t, f.registerWith(t, email, "proveninvitee", code))
		if n := len(f.out.Messages(iam.MessageVerification, email)); n != 0 {
			t.Fatalf("the emailed invitation's invitee was sent %d more codes", n)
		}
		u, err := f.auth.User(t.Context(), iam.UserByEmail(email))
		noError(t, err)
		if !u.EmailVerified {
			t.Fatal("registering the invited address with its emailed code left it unproven")
		}
		f.joinedOnly(t, u.ID, f.rootReader)

		// Its code reaches the address alone: a host's call gets none either.
		created, err := f.auth.CreateInvitation(t.Context(), iam.SystemIdentity(), iam.RootGroup(), iam.NewInvitation{Email: "hosted@example.com", Role: f.rootReader})
		noError(t, err)
		if !created.Emailed || created.Code != "" || created.URL != "" {
			t.Fatalf("an emailed invitation answered its code to its creator: %+v", created)
		}

		// Another address proves itself with a code.
		f.invite(t, owner.AccessToken, "addressed@example.com", f.rootReader, http.StatusAccepted)
		forwarded := fragmentValue(t, f.out.Last(t, iam.MessageInvite, "addressed@example.com").Link, "invite_code")
		f.registerInvited(t, "forwarded@example.com", "forwardedinvitee", forwarded)
	})
	t.Run("AK-J49-C05_an_administrator_invites_a_team_at_once_under_a_budget_of_its_own", func(t *testing.T) {
		f := newFixture(t, authtest.WithConfig(func(c *authkit.Config) {
			config.Tune(c, func(tn *config.Tuning) { tn.NoRateLimits = false })
		}))
		_, owner := f.rootOwner(t)
		_, other := f.rootOwner(t)
		budget := httpapi.DefaultRateLimits()["invite_create_account"].Limit
		if budget < 10 {
			t.Fatalf("an inviter's budget of %d invitations does not invite a team", budget)
		}
		for i := range budget {
			f.invite(t, owner.AccessToken, fmt.Sprintf("teammate%d@example.com", i), f.rootReader, http.StatusAccepted)
		}
		r := f.call(t, "POST", "/groups/root/invitations", owner.AccessToken, map[string]string{"email": "one-too-many@example.com", "role": f.rootReader.String()})
		r.want(t, http.StatusTooManyRequests, "rate_limited")
		var env iam.ErrorEnvelope
		decode(t, r.body, &env)
		if env.Error.Metadata["action"] != "invite_create_account" || r.header.Get("Retry-After") == "" {
			t.Fatalf("the refusal is not the inviter's own budget: %s", r.body)
		}
		// Another administrator at the same address keeps a budget of its own.
		f.invite(t, other.AccessToken, "one-too-many@example.com", f.rootReader, http.StatusAccepted)
	})
	t.Run("AK-J49-C06_an_expired_or_revoked_invitation_registers_nobody", func(t *testing.T) {
		f := newFixture(t, authtest.WithDeps(func(d *authkit.Deps) { d.Email = nil }))
		_, owner := f.rootOwner(t)
		revoke := func(_ string, inv iam.InvitationCreated) {
			f.call(t, "DELETE", "/groups/root/invitations/"+inv.Invitation.ID, owner.AccessToken, nil).want(t, http.StatusNoContent, "")
		}
		expire := func(table string, inv iam.InvitationCreated) {
			_, err := f.pool.Exec(t.Context(), "UPDATE "+pgx.Identifier{f.schema, table}.Sanitize()+" SET expires_at=statement_timestamp()-interval '1 second' WHERE id=$1", inv.Invitation.ID)
			noError(t, err)
		}
		for i, c := range []struct {
			email, table, refusal string
			spoil                 func(string, iam.InvitationCreated)
		}{
			{"", "group_invite_links", "invitation_revoked", revoke},
			{"", "group_invite_links", "invitation_expired", expire},
			{"revoked@example.com", "account_registration_invites", "invitation_revoked", revoke},
			{"expired@example.com", "account_registration_invites", "invitation_expired", expire},
		} {
			inv := f.invite(t, owner.AccessToken, c.email, f.rootReader, http.StatusCreated)
			c.spoil(c.table, inv)
			address := fmt.Sprintf("spoiled%d@example.com", i)
			f.registerWith(t, address, fmt.Sprintf("spoiled%d", i), inv.Code).want(t, http.StatusBadRequest, c.refusal)
			f.noAccount(t, address)
		}
	})
}
