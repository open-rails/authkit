// Command contract writes the e2e server's mounted route catalog into
// src/client/generated. The error codes come from go generate
// ./internal/errmodel in the AuthKit module.
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"log"
	"os"
	"path/filepath"
	"sort"

	"github.com/open-rails/authkit/sdk/auth-ui/e2e/server/harness"
)

type route struct {
	Method     string `json:"method"`
	Path       string `json:"path"`
	Group      string `json:"group"`
	Auth       string `json:"auth"`
	Permission string `json:"permission,omitempty"`
}

type contract struct {
	Routes []route `json:"routes"`
}

func main() {
	out := flag.String("out", "../../src/client/generated", "output directory")
	dsn := flag.String("dsn", os.Getenv("DATABASE_URL"), "migratable Postgres DSN")
	flag.Parse()
	if err := run(*out, *dsn); err != nil {
		log.Fatal(err)
	}
}

func run(out, dsn string) error {
	pool, err := harness.Open(context.Background(), dsn)
	if err != nil {
		return err
	}
	defer pool.Close()
	rt, err := harness.New("http://localhost", pool)
	if err != nil {
		return err
	}
	defer rt.Close()

	var c contract
	for _, r := range rt.Routes() {
		c.Routes = append(c.Routes, route{Method: r.Method, Path: r.Path, Group: string(r.Group), Auth: string(r.Auth), Permission: r.Permission})
	}
	sort.Slice(c.Routes, func(i, j int) bool {
		if c.Routes[i].Path != c.Routes[j].Path {
			return c.Routes[i].Path < c.Routes[j].Path
		}
		return c.Routes[i].Method < c.Routes[j].Method
	})

	if err := os.MkdirAll(out, 0o755); err != nil {
		return err
	}
	var js bytes.Buffer
	enc := json.NewEncoder(&js)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	if err := enc.Encode(c); err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(out, "authkit-contract.json"), js.Bytes(), 0o644)
}
