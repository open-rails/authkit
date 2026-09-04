package authhttp

import (
	"fmt"
	"net/http"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"
)

// #326: concurrent registrations of one username produce exactly one account
// and typed username_in_use refusals for the rest — never a 500 from the raw
// unique violation the check-then-insert race loser used to surface.
func TestRegisterConcurrentSameUsernameIsTyped(t *testing.T) {
	srv, err := NewServer(newServerClient(t, newServerTestConfig(), newServerTestPool(t)), WithoutRateLimiter())
	require.NoError(t, err)
	t.Cleanup(srv.Close)

	username := "racer" + uniqueSuffix()[8:]
	const n = 8
	start := make(chan struct{})
	codes := make([]int, n)
	bodies := make([]string, n)
	var wg sync.WaitGroup
	wg.Add(n)
	for i := 0; i < n; i++ {
		go func(i int) {
			defer wg.Done()
			<-start
			body := fmt.Sprintf(`{"identifier":"%s-%d@example.com","username":"%s","password":"Correct-password-12345"}`, username, i, username)
			rec := serveJSON(srv, http.MethodPost, "/register", body)
			codes[i], bodies[i] = rec.Code, rec.Body.String()
		}(i)
	}
	close(start)
	wg.Wait()

	accepted := 0
	for i, code := range codes {
		switch code {
		case http.StatusAccepted:
			accepted++
		case http.StatusBadRequest:
			require.Contains(t, bodies[i], "username_in_use", "loser %d must get the typed conflict", i)
		default:
			t.Fatalf("registration %d: status %d body %s", i, code, bodies[i])
		}
	}
	require.Equal(t, 1, accepted, "exactly one registration may win the username")
}
