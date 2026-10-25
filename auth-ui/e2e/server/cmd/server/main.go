// Command server is a loopback-only real AuthKit fixture, never a deployment entrypoint.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/open-rails/authkit/auth-ui/e2e/server/harness"
	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/helpers/notify"
)

func main() {
	addr := flag.String("addr", "127.0.0.1:4780", "loopback listener")
	origin := flag.String("origin", "http://localhost:4780", "browser origin")
	dist := flag.String("dist", "", "built auth-ui package")
	app := flag.String("app", "", "built critical host application")
	flag.Parse()
	host, _, err := net.SplitHostPort(*addr)
	if err != nil || net.ParseIP(host) == nil || !net.ParseIP(host).IsLoopback() {
		log.Fatal("critical fixture requires a loopback listener")
	}
	if err := run(*addr, *origin, *dist, *app); err != nil {
		log.Fatal(err)
	}
}

func run(addr, origin, dist, app string) error {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	pool, err := pgxpool.New(ctx, os.Getenv("DATABASE_URL"))
	if err != nil {
		return err
	}
	defer pool.Close()
	rt, err := harness.New(ctx, origin, "critical_ui", pool, "main")
	if err != nil {
		return err
	}
	defer rt.Close(context.WithoutCancel(ctx))
	if err = rt.Start(ctx); err != nil {
		return err
	}
	limited, err := harness.New(ctx, origin+"/limited", "critical_ui_limited", pool, "limited")
	if err != nil {
		return err
	}
	defer limited.Close(context.WithoutCancel(ctx))
	if err = limited.Start(ctx); err != nil {
		return err
	}
	unproved, err := harness.New(ctx, origin+"/unproved", "critical_ui_unproved", pool, "unproved")
	if err != nil {
		return err
	}
	defer unproved.Close(context.WithoutCancel(ctx))
	if err = unproved.Start(ctx); err != nil {
		return err
	}
	mux := http.NewServeMux()
	if err = rt.Mount(mux); err != nil {
		return err
	}
	if err = limited.Mount(mux); err != nil {
		return err
	}
	if err = unproved.Mount(mux); err != nil {
		return err
	}
	fixture(mux, rt, unproved)
	mux.Handle("GET /__package/", http.StripPrefix("/__package/", http.FileServer(http.Dir(dist))))
	mux.Handle("GET /__app/", http.StripPrefix("/__app/", http.FileServer(http.Dir(app))))
	mux.HandleFunc("GET /", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = fmt.Fprint(w, `<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><link rel="stylesheet" href="/__package/styles.css"><title>AuthKit critical integration</title></head><body><div id="root"></div><script type="module" src="/__app/app.js"></script></body></html>`)
	})
	srv := &http.Server{Addr: addr, Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	failed := make(chan error, 1)
	go func() { failed <- srv.ListenAndServe() }()
	select {
	case err := <-failed:
		if !errors.Is(err, http.ErrServerClosed) {
			return err
		}
	case <-ctx.Done():
	}
	stop, done := context.WithTimeout(context.Background(), 5*time.Second)
	defer done()
	return srv.Shutdown(stop)
}

func reply(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if value != nil {
		_ = json.NewEncoder(w).Encode(value)
	}
}

// All controls seed through trusted public host methods. Outcomes under test are
// observed through the real SDK/HTTP surface; no direct table mutations exist.
func fixture(mux *http.ServeMux, rt, unproved *harness.Runtime) {
	mux.HandleFunc("POST /__fixture/notification", func(w http.ResponseWriter, r *http.Request) {
		var in struct {
			UserID, ID string
			Revision   int64
			Withdrawn  bool
		}
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 8192)).Decode(&in); err != nil {
			reply(w, 400, map[string]string{"error": err.Error()})
			return
		}
		publisher, err := rt.Notifications("application")
		if err == nil {
			err = publisher.Apply(r.Context(), []notify.Mutation{{Input: notify.Input{Recipient: notify.Recipient{Audience: notify.AudienceUser, ID: in.UserID}, Origin: notify.Origin{ID: in.ID}, Kind: "export.ready", Data: json.RawMessage(`{"export_id":"browser"}`), CreatedAt: time.Unix(1700000000, 0)}, Revision: in.Revision, Withdrawn: in.Withdrawn}})
		}
		if err != nil {
			reply(w, 400, map[string]string{"error": err.Error()})
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})

	mux.HandleFunc("GET /__fixture/deliveries", func(w http.ResponseWriter, r *http.Request) {
		outbox := rt.Outbox
		if r.URL.Query().Get("profile") == "unproved" {
			outbox = unproved.Outbox
		}
		reply(w, 200, outbox.Messages("", r.URL.Query().Get("to")))
	})
	mux.HandleFunc("POST /__fixture/user", func(w http.ResponseWriter, r *http.Request) {
		var in struct {
			Email, Phone, Username, Password, RootRole string
			Verified                                   bool
		}
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 8192)).Decode(&in); err != nil {
			reply(w, 400, map[string]string{"error": err.Error()})
			return
		}
		u, err := rt.CreateUser(r.Context(), iam.NewUser{Email: in.Email, Phone: in.Phone, Username: in.Username, Password: in.Password, EmailVerified: in.Verified && in.Email != "", PhoneVerified: in.Verified && in.Phone != ""})
		if err == nil && in.RootRole != "" {
			var role iam.Role
			role, err = rt.Role("root:" + in.RootRole)
			if err == nil {
				_, err = rt.EnsureUserRole(r.Context(), iam.RootGroup(), iam.UserByID(u.ID), role)
			}
		}
		if err != nil {
			reply(w, 400, map[string]string{"error": err.Error()})
			return
		}
		reply(w, 201, u)
	})
	mux.HandleFunc("POST /__fixture/group", func(w http.ResponseWriter, r *http.Request) {
		var in struct{ UserID, Role string }
		if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
			reply(w, 400, map[string]string{"error": err.Error()})
			return
		}
		persona, err := rt.Persona(harness.Persona)
		if err != nil {
			reply(w, 500, map[string]string{"error": err.Error()})
			return
		}
		g, err := rt.CreateGroup(r.Context(), iam.NewGroup{Persona: persona})
		if err == nil && in.UserID != "" {
			if in.Role == "" {
				in.Role = "manager"
			}
			var role iam.Role
			role, err = rt.Role(harness.Persona + ":" + in.Role)
			if err == nil {
				_, err = rt.EnsureUserRole(r.Context(), iam.GroupByID(g.ID), iam.UserByID(in.UserID), role)
			}
		}
		if err != nil {
			reply(w, 400, map[string]string{"error": err.Error()})
			return
		}
		reply(w, 201, g)
	})
	mux.HandleFunc("POST /__fixture/mfa-required", func(w http.ResponseWriter, r *http.Request) {
		var in struct {
			UserID   string
			Required bool
		}
		if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
			reply(w, 400, map[string]string{"error": err.Error()})
			return
		}
		u, err := rt.UpdateUser(r.Context(), iam.SystemIdentity(), in.UserID, iam.UserUpdate{MFARequired: &in.Required})
		if err != nil {
			reply(w, 400, map[string]string{"error": err.Error()})
			return
		}
		reply(w, 200, u)
	})
}
