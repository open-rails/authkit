package engine

import (
	"context"
	"testing"

	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/internal/httpapi"
	"github.com/stretchr/testify/require"
)

// fixtureBackend is the engine behind an HTTP service.
func fixtureBackend(b httpapi.Backend) *Engine { return b.(*Engine) }

func newTestService(r *Engine, cfg httpapi.Config) (*httpapi.Service, error) {
	return httpapi.New(r, r.Verifier(), cfg)
}

// groupRoleOps is the engine's role surface the fixtures drive.
type groupRoleOps interface {
	AssignGroupRoles(context.Context, iam.Actor, iam.GroupRef, []iam.Subject, iam.Role) ([]iam.OpResult, error)
	UnassignGroupRoles(context.Context, iam.Actor, iam.GroupRef, []iam.Subject, iam.Role) ([]iam.OpResult, error)
	RemoveGroupMembers(context.Context, iam.Actor, iam.GroupRef, []iam.Subject) ([]iam.OpResult, error)
}

// itemErr is the outcome of a single-item batch call.
func itemErr(res []iam.OpResult, err error) error {
	if err != nil {
		return err
	}
	return res[0].Err
}

func assignRole(ctx context.Context, g groupRoleOps, a iam.Actor, ref iam.GroupRef, subject iam.Subject, role iam.Role) error {
	return itemErr(g.AssignGroupRoles(ctx, a, ref, []iam.Subject{subject}, role))
}

func unassignRole(ctx context.Context, g groupRoleOps, a iam.Actor, ref iam.GroupRef, subject iam.Subject, role iam.Role) error {
	return itemErr(g.UnassignGroupRoles(ctx, a, ref, []iam.Subject{subject}, role))
}

func removeMember(ctx context.Context, g groupRoleOps, a iam.Actor, ref iam.GroupRef, subject iam.Subject) error {
	return itemErr(g.RemoveGroupMembers(ctx, a, ref, []iam.Subject{subject}))
}

// grantRole assigns role with operator authority; the test fails otherwise.
func grantRole(t testing.TB, g groupRoleOps, ref iam.GroupRef, subject iam.Subject, role iam.Role) {
	t.Helper()
	require.NoError(t, assignRole(t.Context(), g, iam.OperatorActor(), ref, subject, role))
}

// revokeRole unassigns role with operator authority; the test fails otherwise.
func revokeRole(t testing.TB, g groupRoleOps, ref iam.GroupRef, subject iam.Subject, role iam.Role) {
	t.Helper()
	require.NoError(t, unassignRole(t.Context(), g, iam.OperatorActor(), ref, subject, role))
}

// seedRole writes an assignment the way bootstrap genesis does, before any
// second factor can exist: no authority rules and no MFA-required-role check.
func seedRole(t testing.TB, e *Engine, ref iam.GroupRef, subject iam.Subject, role iam.Role) {
	t.Helper()
	require.NoError(t, e.withGroupMutation(t.Context(), ref, func(st *permissionGroupStore, g groupTarget) error {
		return st.AssignRole(t.Context(), g.ID, subject, role)
	}))
}
