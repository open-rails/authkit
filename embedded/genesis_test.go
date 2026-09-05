package embedded

import (
	"context"
	"crypto"
	"fmt"
	"testing"
	"time"

	authkit "github.com/open-rails/authkit"
	authcore "github.com/open-rails/authkit/internal/authcore"
	"github.com/open-rails/authkit/internal/testdb"
	"github.com/open-rails/authkit/jwtkit"
	"github.com/stretchr/testify/require"
)

// testKeys builds explicit signing keys (no dev-key generation, nothing
// persisted under the package directory).
func testKeys(t *testing.T) KeysConfig {
	t.Helper()
	s, err := jwtkit.NewRSASigner(2048, "test-kid")
	require.NoError(t, err)
	return KeysConfig{Source: jwtkit.StaticKeySource{Active: s, Pubs: map[string]crypto.PublicKey{s.KID(): s.PublicKey()}}}
}

func newGenesisTestClient(t *testing.T) *Client {
	t.Helper()
	client, err := New(Config{
		Keys:         testKeys(t),
		Token:        TokenConfig{Issuer: "https://example.com", IssuedAudiences: []string{"test-app"}, ExpectedAudiences: []string{"test-app"}},
		Registration: RegistrationConfig{Verification: RegistrationVerificationNone},
		Ephemeral:    EphemeralConfig{AllowMemory: true},
	}, Deps{Postgres: testdb.UnlockedPool(t)})
	require.NoError(t, err)
	return client
}

// #241: the genesis role-grant mutators (no actor check, no no-escalation
// enforcement) are reachable ONLY through Client.Genesis() — an
// explicitly-dangerous seam separate from the actor-checked `*As` methods on
// the main facade. Genesis skips ACTOR checks only: the MFA-required-role
// enrollment gate is a subject-state invariant, not actor authority, and MUST
// hold here too — assigning an MFA-required role (root owner defaults to
// RequiresMFA) to a non-enrolled user fails closed with
// ErrTwoFAEnrollmentRequired on every Genesis mutator, and succeeds once the
// user enrolls 2FA. This proves fail-closed + the full grant/verify/revoke
// flow end-to-end for all Genesis mutators.
func TestGenesisClient_AssignAndRemove(t *testing.T) {
	client := newGenesisTestClient(t)
	ctx := context.Background()

	_, err := client.EnsureRootGroup(ctx)
	require.NoError(t, err)

	suffix := time.Now().UnixNano()
	user, err := client.CreateUser(ctx, fmt.Sprintf("genesis-test-%d@example.com", suffix), fmt.Sprintf("genesis-test-user-%d", suffix))
	require.NoError(t, err)

	// FAIL CLOSED: the root owner role requires MFA; the user has not enrolled.
	err = client.Genesis().AssignGroupRole(ctx, RootPersona, "", user.ID, SubjectKindUser, OwnerRoleName)
	require.ErrorIsf(t, err, authkit.ErrTwoFAEnrollmentRequired,
		"Genesis().AssignGroupRole of an MFA-required role to a non-enrolled user must fail closed, got: %v", err)
	err = client.Genesis().AssignRoleBySlug(ctx, user.ID, OwnerRoleName)
	require.ErrorIsf(t, err, authkit.ErrTwoFAEnrollmentRequired,
		"Genesis().AssignRoleBySlug of an MFA-required role to a non-enrolled user must fail closed, got: %v", err)
	require.NotContains(t, rootRoles(t, client, ctx, user.ID), OwnerRoleName)

	// Enroll 2FA; the SAME calls now succeed.
	_, err = client.impl.Enable2FA(ctx, user.ID, "email", nil, authcore.AllowAdditionalFactors)
	require.NoError(t, err)

	// Genesis().AssignGroupRole grants with NO actor check; RemoveRoleBySlug
	// revokes the same way.
	require.NoError(t, client.Genesis().AssignGroupRole(ctx, RootPersona, "", user.ID, SubjectKindUser, OwnerRoleName))
	require.Contains(t, rootRoles(t, client, ctx, user.ID), OwnerRoleName)
	require.NoError(t, client.Genesis().RemoveRoleBySlug(ctx, user.ID, OwnerRoleName))
	require.NotContains(t, rootRoles(t, client, ctx, user.ID), OwnerRoleName)

	// Genesis().AssignRoleBySlug is the single-role-slug shorthand over the
	// root persona, same actor-unchecked seam.
	require.NoError(t, client.Genesis().AssignRoleBySlug(ctx, user.ID, OwnerRoleName))
	require.Contains(t, rootRoles(t, client, ctx, user.ID), OwnerRoleName)
	require.NoError(t, client.Genesis().RemoveRoleBySlug(ctx, user.ID, OwnerRoleName))
	require.NotContains(t, rootRoles(t, client, ctx, user.ID), OwnerRoleName)
}

// rootRoles reads one user's live root-group roles via the batch RoleSlugsByUsers (#220).
func rootRoles(t *testing.T, c *Client, ctx context.Context, userID string) []string {
	t.Helper()
	m, err := c.RoleSlugsByUsers(ctx, []string{userID})
	require.NoError(t, err)
	return m[userID]
}
