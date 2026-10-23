package iam_test

import (
	"encoding/json"
	"testing"

	"github.com/open-rails/authkit/iam"
	"github.com/stretchr/testify/require"
)

func TestEventDiscriminatorAliases(t *testing.T) {
	for _, raw := range []string{`{"type":"future.changed"}`, `{"kind":"future.changed"}`, `{"type":"future.changed","kind":"future.changed"}`} {
		var event iam.Event
		require.NoError(t, json.Unmarshal([]byte(raw), &event))
		require.Equal(t, iam.EventKind("future.changed"), event.Type)
		require.Equal(t, event.Type, event.Kind)
	}
	for _, event := range []iam.Event{{Type: iam.EventUserRegistered}, {Kind: iam.EventUserRegistered}} {
		raw, err := json.Marshal(event)
		require.NoError(t, err)
		var object map[string]any
		require.NoError(t, json.Unmarshal(raw, &object))
		require.Equal(t, "user.registered", object["type"])
		require.Equal(t, object["type"], object["kind"])
	}
	var event iam.Event
	require.Error(t, json.Unmarshal([]byte(`{"type":"one","kind":"two"}`), &event))
	_, err := json.Marshal(iam.Event{Type: "one", Kind: "two"})
	require.Error(t, err)
}
