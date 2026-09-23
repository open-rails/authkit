// Command server runs a real AuthKit HTTP surface on Postgres for auth-ui's
// Playwright suite. Test-only: it exposes captured email/SMS at /__test/outbox.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	authkithttp "github.com/open-rails/authkit/adapters/http"

	"github.com/open-rails/auth-ui/e2e/server/harness"
)

func main() {
	addr := flag.String("addr", "127.0.0.1:4780", "listen address")
	baseURL := flag.String("base-url", "", "public origin (default http://localhost:<port>)")
	dsn := flag.String("dsn", os.Getenv("DATABASE_URL"), "Postgres DSN")
	static := flag.String("static", "", "directory served at /")
	lifetime := flag.Duration("lifetime", 30*time.Minute, "exit after this long")
	flag.Parse()
	if *baseURL == "" {
		_, port, err := net.SplitHostPort(*addr)
		if err != nil {
			log.Fatal(err)
		}
		*baseURL = "http://localhost:" + port
	}
	if err := run(*addr, *baseURL, *dsn, *static, *lifetime); err != nil {
		log.Fatal(err)
	}
}

func run(addr, baseURL, dsn, static string, lifetime time.Duration) error {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	ctx, cancel := context.WithTimeout(ctx, lifetime)
	defer cancel()

	pool, err := harness.Open(ctx, dsn)
	if err != nil {
		return err
	}
	defer pool.Close()
	rt, err := harness.New(baseURL, pool)
	if err != nil {
		return err
	}
	defer rt.Close()
	if err := rt.Start(ctx); err != nil {
		return err
	}

	routes, err := authkithttp.Routes(rt.Runtime)
	if err != nil {
		return err
	}
	mux := http.NewServeMux()
	if err := routes.Mount(mux); err != nil {
		return err
	}
	mux.HandleFunc("GET /__test/outbox", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(rt.Outbox.List(r.URL.Query().Get("to")))
	})
	// Ages the user's sessions past the sensitive-action window, so the next
	// refreshed token demands a step-up.
	mux.HandleFunc("POST /__test/stale-sessions", func(w http.ResponseWriter, r *http.Request) {
		_, err := pool.Exec(r.Context(), `UPDATE `+harness.Schema+`.refresh_sessions
			SET last_authenticated_at = now() - interval '1 hour'
			WHERE user_id = (SELECT id FROM `+harness.Schema+`.users WHERE email = $1)`,
			r.URL.Query().Get("email"))
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})
	if static != "" {
		mux.Handle("GET /", http.FileServer(http.Dir(static)))
	}

	srv := &http.Server{Addr: addr, Handler: mux, ReadHeaderTimeout: 10 * time.Second}
	errc := make(chan error, 1)
	go func() { errc <- srv.ListenAndServe() }()
	log.Printf("auth-ui e2e server on %s (%s)", addr, baseURL)
	select {
	case err := <-errc:
		return err
	case <-ctx.Done():
	}
	shutdown, done := context.WithTimeout(context.Background(), 5*time.Second)
	defer done()
	return srv.Shutdown(shutdown)
}
