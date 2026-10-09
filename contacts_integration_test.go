package authkit_test

import (
	"context"
	"testing"

	"github.com/open-rails/helpers/contacts"
	"github.com/open-rails/helpers/contacts/contactstest"
	"github.com/stretchr/testify/require"

	"github.com/open-rails/authkit/authtest"
	"github.com/open-rails/authkit/iam"
)

// TestContactsSource: the Client is a helpers/contacts.Source reading the
// accounts as they are now: verified email, username as the name; a deleted
// account is not a contact.
func TestContactsSource(t *testing.T) {
	auth, _ := authtest.New(t)
	ctx := context.Background()
	alice, bob, gone := authtest.NewUser(t, auth), authtest.NewUser(t, auth), authtest.NewUser(t, auth)
	_, err := auth.DeleteUsers(ctx, iam.SystemIdentity(), []string{gone.ID})
	require.NoError(t, err)
	contact := func(u authtest.User) contacts.Contact {
		return contacts.Contact{ID: u.ID, Email: u.Email, Name: u.Username, Username: u.Username}
	}
	contactstest.Check(t, auth, contactstest.Fixtures{
		Contacts: []contacts.Contact{contact(alice), contact(bob)},
		Unknown:  []string{"0192f6a0-0000-7000-8000-00000000c0de", gone.ID},
		Change: func(c contacts.Contact) contacts.Contact {
			email, name, verified := "changed-"+c.Email, "changed"+c.ID[len(c.ID)-8:], true
			_, err := auth.UpdateUser(ctx, iam.SystemIdentity(), c.ID, iam.UserUpdate{Email: &email, Username: &name, EmailVerified: &verified})
			require.NoError(t, err)
			return contacts.Contact{ID: c.ID, Email: email, Name: name, Username: name}
		},
	})

	unproven := "unproven-" + alice.Email
	_, err = auth.UpdateUser(ctx, iam.SystemIdentity(), alice.ID, iam.UserUpdate{Email: &unproven})
	require.NoError(t, err)
	got, err := auth.Contacts(ctx, []string{alice.ID})
	require.NoError(t, err)
	require.Empty(t, got[alice.ID].Email, "an unverified address is not a contact")
	found, err := auth.SearchContacts(ctx, unproven, 10)
	require.NoError(t, err)
	require.Empty(t, found, "nor found by search")
}
