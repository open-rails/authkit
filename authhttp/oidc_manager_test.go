package authhttp

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestOIDCManagerBuiltOnce(t *testing.T) {
	s := newTestService(t)
	m1 := s.oidcManager()
	m2 := s.oidcManager()
	require.Same(t, m1, m2, "oidcManager should return the same instance")
}

