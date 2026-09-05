package embedded

import "testing"

// mustNewService is NewService for tests: a config the constructor rejects fails the test.
func mustNewWithKeys(t testing.TB, cfg Config, keys Keyset, opts ...Option) *Client {
	t.Helper()
	svc, err := NewWithKeys(cfg, keys, depsOf(opts...))
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}
	return svc
}
