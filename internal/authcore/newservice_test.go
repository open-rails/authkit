package authcore

import "testing"

// mustNewService is NewService for tests: a config the constructor rejects fails the test.
func mustNewService(t testing.TB, cfg Config, keys Keyset, opts ...Option) *Service {
	t.Helper()
	svc, err := NewService(cfg, keys, depsOf(opts...))
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}
	return svc
}
