package rootsnapshot

import (
	"fmt"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
)

func TestRootSnapshotBoundsAndCompleteness(t *testing.T) {
	issuer, group := "https://issuer.test", uuid.NewString()
	value, err := New(issuer, group, nil)
	require.NoError(t, err)
	require.NotNil(t, value.Grants)
	parsed, err := Parse(value, issuer)
	require.NoError(t, err)
	require.True(t, parsed.Complete)
	grants := make([]string, MaxGrants+1)
	for i := range grants {
		grants[i] = fmt.Sprintf("root:r%d:read", i)
	}
	_, err = New(issuer, group, grants)
	require.ErrorIs(t, err, ErrInvalid)
	_, err = New(issuer, group, []string{"root:" + strings.Repeat("x", MaxBytes) + ":read"})
	require.ErrorIs(t, err, ErrInvalid)
	value, err = New(issuer, group, []string{"root:*", "root:*", "root:posts:read"})
	require.NoError(t, err)
	require.Len(t, value.Grants, 2)
	for _, mutate := range []func(*Value){
		func(v *Value) { v.GroupID = uuid.Nil.String() },
		func(v *Value) { v.Issuer = "https://foreign.test" },
		func(v *Value) { v.Grants = nil },
		func(v *Value) { v.Grants = []string{"*"} },
		func(v *Value) { v.Grants = []string{"project:*"} },
		func(v *Value) { v.Grants = []string{"root:*", "root:*"} },
		func(v *Value) { v.Grants = grants },
	} {
		bad := *value
		mutate(&bad)
		_, err := Parse(&bad, issuer)
		require.ErrorIs(t, err, ErrInvalid)
	}
	value.Complete = false
	parsed, err = Parse(value, issuer)
	require.NoError(t, err)
	require.Nil(t, parsed)
	parsed, err = Parse(map[string]any{"v": 2}, issuer)
	require.NoError(t, err)
	require.Nil(t, parsed)
	for _, raw := range []any{nil, []any{}, map[string]any{}, map[string]any{"v": "1"}} {
		_, err := Parse(raw, issuer)
		require.ErrorIs(t, err, ErrInvalid)
	}
}
