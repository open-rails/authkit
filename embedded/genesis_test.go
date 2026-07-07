package embedded

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	authkit "github.com/open-rails/authkit"
	"github.com/stretchr/testify/require"
)

func newGenesisTestPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	dsn := os.Getenv("AUTHKIT_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("AUTHKIT_TEST_DATABASE_URL not set; skipping DB-backed test")
	}
	pool, err := pgxpool.New(context.Background(), dsn)
	require.NoError(t, err)
	t.Cleanup(pool.Close)
	return pool
}

func newGenesisTestClient(t *testing.T) *Client {
	t.Helper()
	client, err := New(Config{
		Keys:         KeysConfig{AllowEphemeralDevKeys: true},
		Token:        TokenConfig{Issuer: "https://example.com", IssuedAudiences: []string{"test-app"}, ExpectedAudiences: []string{"test-app"}},
		Registration: RegistrationConfig{Verification: RegistrationVerificationNone},
	}, newGenesisTestPool(t))
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
	_, err = client.impl.Enable2FA(ctx, user.ID, "email", nil)
	require.NoError(t, err)

	// Genesis().AssignGroupRole grants with NO actor check.
	require.NoError(t, client.Genesis().AssignGroupRole(ctx, RootPersona, "", user.ID, SubjectKindUser, OwnerRoleName))
	require.Contains(t, rootRoles(t, client, ctx, user.ID), OwnerRoleName)

	// Genesis().RemoveGroupSubject revokes with NO actor check.
	require.NoError(t, client.Genesis().RemoveGroupSubject(ctx, RootPersona, "", user.ID, SubjectKindUser))
	require.NotContains(t, rootRoles(t, client, ctx, user.ID), OwnerRoleName)

	// Genesis().AssignRoleBySlug / RemoveRoleBySlug are the single-role-slug
	// shorthand over the root persona, same actor-unchecked seam.
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
