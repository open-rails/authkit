package remote_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"testing"
	"time"

	authkit "github.com/open-rails/authkit"
	"github.com/open-rails/authkit/documents"
	"github.com/open-rails/authkit/remote"
	"github.com/open-rails/authkit/server"
	"github.com/stretchr/testify/require"
)

// fakeClient is an authkit.Client whose unimplemented methods panic (via the
// embedded interface); the test overrides only the ones it exercises. It proves
// remote.Client round-trips the generic /v1/call transport — values, multi-return,
// pointer results, and error IDENTITY — without the engine or a DB.
type fakeClient struct {
	authkit.Client
}

var documentWireErrors = []error{
	documents.ErrInvalidReference, documents.ErrInvalidType, documents.ErrInvalidDigest,
	documents.ErrDuplicateReference, documents.ErrTooManyReferences, documents.ErrReferencesTooLarge,
	documents.ErrWrongTokenType, documents.ErrReservedAttribute, documents.ErrInvalidEnvelope,
	documents.ErrPayloadTooLarge, documents.ErrMalformedJWS, documents.ErrWrongJOSEType,
	documents.ErrUnsupportedAlgorithm, documents.ErrUnsupportedSigner, documents.ErrUnknownKey,
	documents.ErrInvalidSignature, documents.ErrDigestMismatch, documents.ErrIssuerMismatch,
	documents.ErrAudienceMismatch, documents.ErrTypeMismatch, documents.ErrUntrustedIssuer,
	documents.ErrUnauthorized, documents.ErrNotFound, documents.ErrFetch, documents.ErrRedirect,
}

func (fakeClient) Can(_ context.Context, _, _, _, _, perm string) (bool, error) {
	return perm == "root:users:ban", nil
}
func (fakeClient) ListEffectivePermissions(_ context.Context, _, _, _, _ string) ([]string, error) {
	return []string{"root:users:ban", "root:content:moderate"}, nil
}
func (fakeClient) IsUserAllowed(_ context.Context, userID string) (bool, error) {
	if userID == "missing" {
		return false, authkit.ErrUserNotFound
	}
	return userID != "banned", nil
}
func (fakeClient) CreateUser(_ context.Context, email, username string) (*authkit.User, error) {
	if email == "taken@example.com" {
		return nil, authkit.ErrEmailInUse
	}
	if email == "wrapped@example.com" {
		// The shape exposed methods actually return (#197): a WRAPPED sentinel whose
		// err.Error() is NOT a bare registry key.
		return nil, fmt.Errorf("%w: smtp: connection refused", authkit.ErrEmailDeliveryFailed)
	}
	return &authkit.User{ID: "u-new", Email: &email, Username: &username}, nil
}
func (fakeClient) MintAPIKey(_ context.Context, persona, instanceSlug, name, role, createdBy string, _ *time.Time) (authkit.APIKey, string, error) {
	return authkit.APIKey{ID: "k1", Name: name, Role: role}, "secret-" + name, nil
}
func (fakeClient) MintDelegatedAccessToken(_ context.Context, params authkit.DelegatedAccessParams) (string, error) {
	return params.Documents["example.entitlements/v1"], nil
}
func (fakeClient) SignDocument(_ context.Context, envelope authkit.DocumentEnvelope) (authkit.SignedDocument, error) {
	for _, sentinel := range documentWireErrors {
		if envelope.Type == sentinel.Error() {
			return authkit.SignedDocument{}, fmt.Errorf("wrapped document error: %w", sentinel)
		}
	}
	return authkit.SignedDocument{
		CompactJWS: "signed", Reference: authkit.DocumentReference{Type: envelope.Type, Digest: "sha256:remote"},
		SignedPayload: append([]byte(nil), envelope.Payload...),
	}, nil
}
func (fakeClient) HasEmailSender() bool { return true }

func TestRemoteParity(t *testing.T) {
	ts := httptest.NewServer(server.NewHandler(fakeClient{}, "s3cret"))
	defer ts.Close()
	rc := remote.New(ts.URL, "s3cret")
	ctx := context.Background()

	// bool round-trip (true and false).
	ok, err := rc.Can(ctx, "u1", "user", "root", "", "root:users:ban")
	require.NoError(t, err)
	require.True(t, ok)
	ok, err = rc.Can(ctx, "u1", "user", "root", "", "root:nope")
	require.NoError(t, err)
	require.False(t, ok)

	// []string round-trip.
	perms, err := rc.ListEffectivePermissions(ctx, "u1", "user", "root", "")
	require.NoError(t, err)
	require.Equal(t, []string{"root:users:ban", "root:content:moderate"}, perms)

	// pointer-struct result round-trip.
	u, err := rc.CreateUser(ctx, "a@b.com", "alice")
	require.NoError(t, err)
	require.Equal(t, "u-new", u.ID)
	require.NotNil(t, u.Username)
	require.Equal(t, "alice", *u.Username)

	// multi-return round-trip (APIKey + secret string).
	key, secret, err := rc.MintAPIKey(ctx, "root", "", "ci", "admin", "owner", nil)
	require.NoError(t, err)
	require.Equal(t, "k1", key.ID)
	require.Equal(t, "secret-ci", secret)

	// New document fields survive the generated client/server transport.
	digest, err := rc.MintDelegatedAccessToken(ctx, authkit.DelegatedAccessParams{
		Documents: map[string]string{"example.entitlements/v1": "sha256:delegated"},
	})
	require.NoError(t, err)
	require.Equal(t, "sha256:delegated", digest)
	signed, err := rc.SignDocument(ctx, authkit.DocumentEnvelope{
		Type: "example.entitlements/v1", Payload: json.RawMessage(`{"limit":7}`),
	})
	require.NoError(t, err)
	require.Equal(t, "example.entitlements/v1", signed.Reference.Type)
	require.True(t, bytes.Equal([]byte(`{"limit":7}`), signed.SignedPayload))
	for _, sentinel := range documentWireErrors {
		t.Run(sentinel.Error(), func(t *testing.T) {
			_, err := rc.SignDocument(ctx, authkit.DocumentEnvelope{Type: sentinel.Error()})
			require.ErrorIs(t, err, sentinel)
		})
	}

	// no-ctx / no-error method.
	require.True(t, rc.HasEmailSender())

	// error IDENTITY survives the wire (sentinel re-derived from the code).
	_, err = rc.IsUserAllowed(ctx, "missing")
	require.ErrorIs(t, err, authkit.ErrUserNotFound)
	_, err = rc.CreateUser(ctx, "taken@example.com", "bob")
	require.ErrorIs(t, err, authkit.ErrEmailInUse)

	// #197: a WRAPPED sentinel also survives the wire. The server must resolve the
	// code chain-aware (CodeForError) — emitting err.Error() verbatim would produce
	// a non-registry code and errors.Is identity would be lost.
	_, err = rc.CreateUser(ctx, "wrapped@example.com", "carol")
	require.ErrorIs(t, err, authkit.ErrEmailDeliveryFailed)

	// auth seam: a wrong token is rejected.
	bad := remote.New(ts.URL, "wrong")
	_, err = bad.Can(ctx, "u1", "user", "root", "", "root:users:ban")
	require.Error(t, err)
}
