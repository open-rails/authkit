// Command schemaproof proves that the working tree's migrations build exactly
// the database another revision's migrations build. It applies each tree's
// AuthKit chain through migratekit, as Migrate does, and then its account
// inbox chain, to scratch databases in two schemas, and requires identical
// pg_dump output: schema and data with privileges, without owners. pg_dump
// orders objects itself, so the files' own layout does not matter.
//
//	go run ./scripts/schemaproof [-ref origin/master] [-dsn URL] [-pg-dump COMMAND]
//
// -dsn (or AUTHKIT_TEST_DATABASE_URL) names a disposable PostgreSQL 18 server
// whose role may create databases. -pg-dump (or PG_DUMP) is the pg_dump 18
// command, "pg_dump" on PATH by default; CI runs the service container's
// ("docker exec <container> pg_dump"), which must reach the server at the
// DSN's address.
package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io/fs"
	"net/url"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing/fstest"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/open-rails/migratekit"
)

// The two chains, applied in this order.
const (
	authkitDir = "internal/migrations/postgres"
	notifyDir  = "notify/postgres/migrations"
)

// Both chains are built in AuthKit's default schema and in another.
var schemas = []string{"profiles", "schemaproof"}

func main() {
	ref := flag.String("ref", "origin/master", "revision whose migrations are the reference")
	dsn := flag.String("dsn", os.Getenv("AUTHKIT_TEST_DATABASE_URL"), "disposable PostgreSQL 18 server")
	keep := flag.String("keep", "", "directory to keep the dumps in")
	pgDumpCommand := "pg_dump"
	if v := strings.TrimSpace(os.Getenv("PG_DUMP")); v != "" {
		pgDumpCommand = v
	}
	flag.StringVar(&pgDumpCommand, "pg-dump", pgDumpCommand, "the pg_dump 18 command, split on spaces")
	flag.Parse()
	if pgDump = strings.Fields(pgDumpCommand); len(pgDump) == 0 {
		pgDump = []string{"pg_dump"}
	}
	if err := run(context.Background(), *ref, strings.TrimSpace(*dsn), *keep); err != nil {
		fmt.Fprintln(os.Stderr, "schemaproof:", err)
		os.Exit(1)
	}
}

// pgDump is the pg_dump command and its leading arguments.
var pgDump []string

// tree is one revision's two chains.
type tree struct{ authkit, notify fs.FS }

func run(ctx context.Context, ref, dsn, keep string) error {
	if dsn == "" {
		return errors.New("-dsn or AUTHKIT_TEST_DATABASE_URL must name a disposable PostgreSQL server")
	}
	var old tree
	var err error
	if old.authkit, err = filesAt(ctx, ref, authkitDir); err != nil {
		return err
	}
	if old.notify, err = filesAt(ctx, ref, notifyDir); err != nil {
		return err
	}
	work := tree{authkit: os.DirFS(authkitDir), notify: os.DirFS(notifyDir)}
	out := keep
	if out == "" {
		if out, err = os.MkdirTemp("", "schemaproof-"); err != nil {
			return err
		}
		defer os.RemoveAll(out)
	} else if err := os.MkdirAll(out, 0o755); err != nil {
		return err
	}
	for _, t := range []struct {
		name string
		tree tree
	}{{ref, old}, {"working tree", work}} {
		a, _ := fs.Glob(t.tree.authkit, "*.sql")
		n, _ := fs.Glob(t.tree.notify, "*.sql")
		fmt.Printf("%s: %d AuthKit and %d inbox migrations\n", t.name, len(a), len(n))
	}
	for _, schema := range schemas {
		want, err := dump(ctx, dsn, schema, old)
		if err != nil {
			return fmt.Errorf("%s in %s: %w", ref, schema, err)
		}
		got, err := dump(ctx, dsn, schema, work)
		if err != nil {
			return fmt.Errorf("working tree in %s: %w", schema, err)
		}
		wantFile, gotFile := filepath.Join(out, schema+".reference.sql"), filepath.Join(out, schema+".candidate.sql")
		if err := os.WriteFile(wantFile, want, 0o644); err != nil {
			return err
		}
		if err := os.WriteFile(gotFile, got, 0o644); err != nil {
			return err
		}
		if !bytes.Contains(got, []byte("CREATE TABLE "+schema+".users ")) {
			return fmt.Errorf("schema %s: the dump holds no users table", schema)
		}
		if !bytes.Equal(want, got) {
			diff, _ := exec.CommandContext(ctx, "diff", "-u", wantFile, gotFile).CombinedOutput()
			os.Stdout.Write(diff)
			return fmt.Errorf("schema %s: the dumps differ", schema)
		}
		fmt.Printf("schema %s: identical, %d lines (%d bytes)\n", schema, bytes.Count(got, []byte("\n")), len(got))
	}
	return nil
}

// filesAt reads dir's migrations at ref from git.
func filesAt(ctx context.Context, ref, dir string) (fs.FS, error) {
	list, err := exec.CommandContext(ctx, "git", "ls-tree", "--name-only", ref, dir+"/").Output()
	if err != nil {
		return nil, fmt.Errorf("list %s at %s: %w", dir, ref, err)
	}
	files := fstest.MapFS{}
	for _, name := range strings.Fields(string(list)) {
		if !strings.HasSuffix(name, ".sql") {
			continue
		}
		body, err := exec.CommandContext(ctx, "git", "show", ref+":"+name).Output()
		if err != nil {
			return nil, fmt.Errorf("read %s at %s: %w", name, ref, err)
		}
		files[path.Base(name)] = &fstest.MapFile{Data: body}
	}
	if len(files) == 0 {
		return nil, fmt.Errorf("%s has no migrations at %s", dir, ref)
	}
	return files, nil
}

// dump builds t in schema of a scratch database and returns its normalised
// pg_dump.
func dump(ctx context.Context, dsn, schema string, t tree) ([]byte, error) {
	admin, err := pgx.Connect(ctx, dsn)
	if err != nil {
		return nil, err
	}
	defer admin.Close(context.WithoutCancel(ctx))
	var suffix [6]byte
	_, _ = rand.Read(suffix[:])
	name := "schemaproof_" + hex.EncodeToString(suffix[:])
	if _, err := admin.Exec(ctx, "CREATE DATABASE "+pgx.Identifier{name}.Sanitize()); err != nil {
		return nil, err
	}
	defer func() {
		ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
		defer cancel()
		_, _ = admin.Exec(ctx, "DROP DATABASE IF EXISTS "+pgx.Identifier{name}.Sanitize()+" WITH (FORCE)")
	}()
	target, err := url.Parse(dsn)
	if err != nil {
		return nil, err
	}
	target.Path = "/" + name
	pool, err := pgxpool.New(ctx, target.String())
	if err != nil {
		return nil, err
	}
	err = build(ctx, pool, schema, t)
	var oids [2]string
	if err == nil {
		err = pool.QueryRow(ctx, `SELECT d.oid::text, n.oid::text FROM pg_database d, pg_namespace n WHERE d.datname = current_database() AND n.nspname = $1`, schema).Scan(&oids[0], &oids[1])
	}
	pool.Close()
	if err != nil {
		return nil, err
	}
	args := append(pgDump[1:len(pgDump):len(pgDump)], "--dbname="+target.String(), "--schema="+schema, "--no-owner")
	raw, err := exec.CommandContext(ctx, pgDump[0], args...).Output() // #nosec G204 -- the operator's -pg-dump command
	if err != nil {
		var exit *exec.ExitError
		if errors.As(err, &exit) {
			return nil, fmt.Errorf("%s: %w: %s", strings.Join(pgDump, " "), err, bytes.TrimSpace(exit.Stderr))
		}
		return nil, fmt.Errorf("%s: %w", strings.Join(pgDump, " "), err)
	}
	return normalise(raw, oids), nil
}

// build applies the AuthKit chain as Migrate does, then the inbox chain as
// its migrator does: in file order, {{schema}} rendered, in one transaction.
func build(ctx context.Context, pool *pgxpool.Pool, schema string, t tree) error {
	chain, err := migratekit.LoadFromFS(t.authkit)
	if err != nil {
		return err
	}
	m, err := migratekit.NewPostgresFromPGXPool(pool, "authkit")
	if err != nil {
		return err
	}
	defer m.Close()
	if err := m.WithSchema(schema).ApplyMigrations(ctx, chain); err != nil {
		return err
	}
	names, err := fs.Glob(t.notify, "*.sql")
	if err != nil {
		return err
	}
	sort.Strings(names)
	return pgx.BeginFunc(ctx, pool, func(tx pgx.Tx) error {
		for _, name := range names {
			body, err := fs.ReadFile(t.notify, name)
			if err != nil {
				return err
			}
			if _, err := tx.Exec(ctx, strings.ReplaceAll(string(body), "{{schema}}", pgx.Identifier{schema}.Sanitize())); err != nil {
				return fmt.Errorf("inbox migration %s: %w", name, err)
			}
		}
		return nil
	})
}

// normalise drops what pg_dump varies between databases or runs: its header
// comments, session settings and the \restrict key; in rows, the instants,
// UUIDs and the database's and schema's oids.
func normalise(raw []byte, oids [2]string) []byte {
	var out bytes.Buffer
	rows := false
	for line := range strings.Lines(string(raw)) {
		bare := strings.TrimSuffix(line, "\n")
		switch {
		case rows && bare == `\.`:
			rows = false
		case rows:
			fields := strings.Split(bare, "\t")
			for i, f := range fields {
				switch {
				case f == oids[0]:
					fields[i] = "<database oid>"
				case f == oids[1]:
					fields[i] = "<schema oid>"
				case instant.MatchString(f):
					fields[i] = "<instant>"
				case uuidValue.MatchString(f):
					fields[i] = "<uuid>"
				}
			}
			line = strings.Join(fields, "\t") + "\n"
		case strings.HasPrefix(bare, "COPY ") && strings.HasSuffix(bare, " FROM stdin;"):
			rows = true
		case bare == "--",
			strings.HasPrefix(bare, "-- Name: "),
			strings.HasPrefix(bare, "-- Data for Name: "),
			strings.HasPrefix(bare, "-- PostgreSQL database dump"),
			strings.HasPrefix(bare, "-- Dumped "),
			strings.HasPrefix(bare, "SET "),
			strings.HasPrefix(bare, "SELECT pg_catalog.set_config('search_path'"),
			strings.HasPrefix(bare, `\restrict `),
			strings.HasPrefix(bare, `\unrestrict `):
			continue
		}
		out.WriteString(line)
	}
	return out.Bytes()
}

var (
	instant   = regexp.MustCompile(`^\d{4}-\d\d-\d\d \d\d:\d\d:\d\d(\.\d+)?\+00$`)
	uuidValue = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
)
