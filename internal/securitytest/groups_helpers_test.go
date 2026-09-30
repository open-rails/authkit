package securitytest

import (
	"net/url"

	"github.com/stretchr/testify/require"

	"github.com/open-rails/authkit/iam"
)

// inviteCode is the code of the newest invitation emailed to email, the one
// value its link carries: the email is the code's only carrier.
func (h *host) inviteCode(email string) string {
	h.t.Helper()
	link, err := url.Parse(h.mail.Last(h.t, iam.MessageInvite, email).Link)
	require.NoError(h.t, err)
	query, err := url.ParseQuery(link.Fragment)
	require.NoError(h.t, err)
	require.Len(h.t, query, 1, link.String())
	for _, values := range query {
		return values[0]
	}
	return ""
}
