package verify

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	authkit "github.com/open-rails/authkit"
	"github.com/open-rails/authkit/jwtkit"
)

// countingSource is a remote-application store that tallies its calls.
type countingSource struct {
	mu      sync.Mutex
	apps    []authkit.RemoteApplication
	list    int
	get     int
	listErr error
}

func (s *countingSource) ListRemoteApplications(context.Context, bool) ([]authkit.RemoteApplication, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.list++
	if s.listErr != nil {
		return nil, s.listErr
	}
	return append([]authkit.RemoteApplication(nil), s.apps...), nil
}

func (s *countingSource) GetRemoteApplication(_ context.Context, issuer string) (*authkit.RemoteApplication, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.get++
	for _, ra := range s.apps {
		if ra.Issuer == issuer {
			ra := ra
			return &ra, nil
		}
	}
	return nil, authkit.ErrRemoteApplicationNotFound
}

func (s *countingSource) calls() (int, int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.list, s.get
}

func staticApp(t *testing.T, slug, issuer string) (authkit.RemoteApplication, *jwtkit.RSASigner) {
	t.Helper()
	signer, err := jwtkit.NewRSASigner(2048, slug+"-kid")
	require.NoError(t, err)
	der, err := x509.MarshalPKIXPublicKey(signer.PublicKey())
	require.NoError(t, err)
	pemKey := string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))
	return authkit.RemoteApplication{
		Slug: slug, Issuer: issuer, Enabled: true, Mode: authkit.RemoteAppModeStatic,
		PublicKeys: []authkit.RemoteAppKey{{KID: signer.KID(), PublicKeyPEM: pemKey}},
	}, signer
}

func mintFor(t *testing.T, signer *jwtkit.RSASigner, iss string) string {
	t.Helper()
	now := time.Now()
	tok, err := signer.SignWithHeaders(context.Background(), map[string]any{
		"iss": iss, "aud": "aud", "sub": "u1", "iat": now.Add(-time.Minute).Unix(), "exp": now.Add(time.Hour).Unix(),
	}, map[string]any{"typ": AccessTokenType})
	require.NoError(t, err)
	return tok
}

func (v *Verifier) forceStaleSnapshot() {
	v.mu.Lock()
	v.fedSnapshotAt = time.Time{}
	v.mu.Unlock()
}

// TestLazyLoad_UnknownIssuersNeverReachStore pins ak#297: a flood of distinct
// attacker-chosen `iss` values costs at most one ListRemoteApplications per
// snapshot TTL, never a per-issuer store read, and leaves no per-issuer state.
func TestLazyLoad_UnknownIssuersNeverReachStore(t *testing.T) {
	app, signer := staticApp(t, "app", "https://app.example")
	src := &countingSource{apps: []authkit.RemoteApplication{app}}
	v := NewVerifier()
	v.mu.Lock()
	v.fedSource = src
	v.mu.Unlock()

	for i := 0; i < 1000; i++ {
		_, err := v.Verify(context.Background(), mintFor(t, signer, fmt.Sprintf("https://garbage-%d.example", i)))
		require.Error(t, err)
	}
	list, get := src.calls()
	require.Equal(t, 1, list, "one snapshot refresh for the whole flood")
	require.Equal(t, 0, get, "no per-issuer store read")
	stats := v.FederationStats()
	require.Equal(t, 1, stats.Snapshot)
	require.Zero(t, stats.Negative)
	require.Zero(t, stats.InFlight)

	// Values that cannot be a registered issuer never touch the store, even
	// when the snapshot is stale.
	v.forceStaleSnapshot()
	for _, iss := range []string{"garbage", "app.example", strings.Repeat("x", 600), "https://" + strings.Repeat("h", 600) + ".example", "https://a.example/with space", "ftp://a.example"} {
		_, err := v.Verify(context.Background(), mintFor(t, signer, iss))
		require.Error(t, err, iss)
	}
	list, _ = src.calls()
	require.Equal(t, 1, list)

	// The registered application verifies on first use straight from the
	// snapshot (ak#42 contract), still without a per-issuer read.
	_, err := v.Verify(context.Background(), mintFor(t, signer, "https://app.example"))
	require.NoError(t, err)
	_, get = src.calls()
	require.Equal(t, 0, get)
}

// TestLazyLoad_NewApplicationVisibleAfterRefresh: an application enabled after
// the snapshot was taken is picked up on the next refresh; a failing store fails
// closed and is consulted at most once per TTL.
func TestLazyLoad_NewApplicationVisibleAfterRefresh(t *testing.T) {
	app, signer := staticApp(t, "first", "https://first.example")
	src := &countingSource{apps: []authkit.RemoteApplication{app}}
	v := NewVerifier()
	v.mu.Lock()
	v.fedSource = src
	v.mu.Unlock()
	_, err := v.Verify(context.Background(), mintFor(t, signer, "https://first.example"))
	require.NoError(t, err)

	second, signer2 := staticApp(t, "second", "https://second.example")
	src.mu.Lock()
	src.apps = append(src.apps, second)
	src.mu.Unlock()
	_, err = v.Verify(context.Background(), mintFor(t, signer2, "https://second.example"))
	require.Error(t, err, "not visible while the snapshot is fresh")
	v.forceStaleSnapshot()
	_, err = v.Verify(context.Background(), mintFor(t, signer2, "https://second.example"))
	require.NoError(t, err, "visible after the refresh")
	list, get := src.calls()
	require.Equal(t, 2, list)
	require.Equal(t, 0, get)

	src.mu.Lock()
	src.listErr = errors.New("store down")
	src.mu.Unlock()
	v.forceStaleSnapshot()
	_, err = v.Verify(context.Background(), mintFor(t, signer, "https://third.example"))
	require.Error(t, err)
	_, err = v.Verify(context.Background(), mintFor(t, signer, "https://fourth.example"))
	require.Error(t, err)
	list, _ = src.calls()
	require.Equal(t, 3, list, "a failing store is retried at most once per TTL")
	_, err = v.Verify(context.Background(), mintFor(t, signer, "https://first.example"))
	require.NoError(t, err, "already-registered issuers are unaffected by store failure")
}
