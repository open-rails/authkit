package querytest

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/open-rails/authkit/internal/db"
	"github.com/open-rails/authkit/internal/testdb"
)

const (
	perfIssuer  = "https://perf.example"
	perfFatUser = 1   // a non-soft-deleted user given many sessions (fan-out).
	perfFat     = 200 // active sessions on the fat user.
	perfIssuers = 5   // distinct IdP issuers provider links are spread across.
)

// TestQueryPerformance is the scaling gate: it bulk-seeds the growable tables,
// VACUUM ANALYZEs (so the visibility map is set and covering indexes serve
// index-only scans, as on a live autovacuumed DB), then EXPLAIN (ANALYZE,
// BUFFERS)es the REAL generated query text
// (sourced from db.QueryText, never hand-copied) for each distinct hot access
// pattern, asserting no sequential scan / no Sort on the big table plus loose
// time and buffer budgets. Every case runs inside a rolled-back transaction so
// write queries (UPDATE/DELETE) are measured without mutating the shared seed.
//
// The seed is deliberately non-uniform: one "fat" user carries perfFat sessions
// and provider links span perfIssuers issuers, so per-user fan-out and per-issuer
// cardinality costs (sorts, skip scans) actually show up instead of hiding behind
// one-row-per-user data.
//
// Only queries whose efficiency can degrade at scale are gated; PK / unique point
// lookups are O(1) and need no gate. See README.md for the access-pattern
// rationale and the remaining "Findings".
func TestQueryPerformance(t *testing.T) {
	pg := testdb.ScratchPostgres(t)
	ctx := context.Background()
	scale := envInt("QUERY_PERF_SCALE", 100000)

	const rootID = "90000000-0000-4000-8000-000000000000"
	seedPerfData(t, ctx, pg.Pool, rootID, scale)

	// hot = a non-deleted user near the top of the range (scale-1 % 50 != 0).
	hot := scale - 1

	cases := []perfCase{
		{
			Name: "user_by_email", MaxExecutionMS: 50, MaxSharedReadBlocks: 16,
			SQL: db.QueryText["UserByEmail"], Args: []any{perfEmail(hot)},
			ForbidSeqScan: []string{"users"},
		},
		{
			Name: "user_by_username", MaxExecutionMS: 50, MaxSharedReadBlocks: 16,
			SQL: db.QueryText["UserByUsername"], Args: []any{perfUsername(hot)},
			ForbidSeqScan: []string{"users"},
		},
		{
			Name: "users_by_id_array", MaxExecutionMS: 100, MaxSharedReadBlocks: 64,
			SQL:           db.QueryText["IdentityUsersByIDs"],
			Args:          []any{[]string{perfUserID(1), perfUserID(scale / 2), perfUserID(hot)}},
			ForbidSeqScan: []string{"users"},
		},
		{
			Name: "session_by_current_hash", MaxExecutionMS: 50, MaxSharedReadBlocks: 16,
			SQL: db.QueryText["SessionByCurrentTokenHash"], Args: []any{tokenHash(hot), perfIssuer},
			ForbidSeqScan: []string{"refresh_sessions"},
		},
		{
			Name: "session_by_previous_hash", MaxExecutionMS: 50, MaxSharedReadBlocks: 16,
			SQL: db.QueryText["SessionByPreviousTokenHash"], Args: []any{prevHash(hot), perfIssuer},
			ForbidSeqScan: []string{"refresh_sessions"},
		},
		{
			// Targets the fat user (perfFat sessions) so the access path faces real
			// fan-out, not one row.
			Name: "sessions_list_by_user", MaxExecutionMS: 75, MaxSharedReadBlocks: 64,
			SQL: db.QueryText["SessionsListByUser"], Args: []any{perfUserID(perfFatUser), perfIssuer},
			ForbidSeqScan: []string{"refresh_sessions"},
		},
		{
			// Fat user + ORDER BY last_used_at LIMIT. With the (user_id, issuer,
			// last_used_at) index (migration 002) this is index-ordered: no Sort.
			Name: "sessions_evict_oldest", MaxExecutionMS: 75, MaxSharedReadBlocks: 32,
			SQL:           db.QueryText["SessionsEvictOldest"],
			Args:          []any{perfUserID(perfFatUser), perfIssuer, int64(5)},
			ForbidSeqScan: []string{"refresh_sessions"}, ForbidSort: true,
		},
		{
			// Indexed by refresh_sessions_family_active (migration 002); was a full
			// seq scan before.
			Name: "session_revoke_family", MaxExecutionMS: 50, MaxSharedReadBlocks: 16,
			SQL: db.QueryText["SessionsRevokeFamily"], Args: []any{perfFamilyID(hot)},
			ForbidSeqScan: []string{"refresh_sessions"},
		},
		{
			Name: "provider_by_issuer_subject", MaxExecutionMS: 50, MaxSharedReadBlocks: 16,
			SQL: db.QueryText["ProviderLinkByIssuer"], Args: []any{perfIdpIssuer(hot), perfSubject(hot)},
			ForbidSeqScan: []string{"user_providers"},
		},
		{
			Name: "provider_slugs_by_user", MaxExecutionMS: 50, MaxSharedReadBlocks: 16,
			SQL: db.QueryText["UserProviderSlugs"], Args: []any{perfUserID(hot)},
			ForbidSeqScan: []string{"user_providers"},
		},
		{
			// Social-login lookup by (provider_slug, subject). Indexed by
			// user_providers_slug_subject_idx (migration 003); previously leaned on a
			// skip scan whose cost grew with issuer count.
			Name: "provider_by_slug_subject", MaxExecutionMS: 50, MaxSharedReadBlocks: 16,
			SQL: db.QueryText["ProviderLinkBySlug"], Args: []any{"github", perfSubject(hot)},
			ForbidSeqScan: []string{"user_providers"},
		},
		{
			// Bounded by the partial users_deleted_at_idx (touches only deleted rows),
			// then top-N sorts the LIMIT page — the planner's correct choice for a
			// small eligible set, so no ForbidSort here. Gated for no full scan.
			Name: "users_purge_candidates", MaxExecutionMS: 100, MaxSharedReadBlocks: 64,
			SQL: db.QueryText["UsersPurgeCandidates"], Args: []any{time.Now().UTC(), int64(100)},
			ForbidSeqScan: []string{"users"},
		},
		{
			// RAW exception: group-role authorization is dynamic SQL built in
			// internal/authcore/permission_group_store.go, not an sqlc query, so it
			// has no generated constant to source. Kept hand-written and flagged; if
			// authcore's SQL changes this must be updated by hand.
			Name: "root_roles_for_page (raw authcore)", MaxExecutionMS: 100, MaxSharedReadBlocks: 64,
			SQL:           `SELECT user_id::text, role FROM profiles.group_user_roles WHERE permission_group_id = $1::uuid AND user_id = ANY($2::uuid[]) AND deleted_at IS NULL`,
			Args:          []any{rootID, []string{perfUserID(1), perfUserID(scale / 2), perfUserID(hot)}},
			ForbidSeqScan: []string{"group_user_roles"},
		},
	}

	results := make([]perfResult, 0, len(cases))
	for _, c := range cases {
		if strings.TrimSpace(c.SQL) == "" {
			t.Fatalf("%s: empty SQL (missing db.QueryText entry?)", c.Name)
		}
		result := explain(t, ctx, pg.Pool, scale, c)
		results = append(results, result)
		if result.ExecutionMS > c.MaxExecutionMS {
			t.Fatalf("%s execution %.3fms > %.3fms", c.Name, result.ExecutionMS, c.MaxExecutionMS)
		}
		if result.SharedReadBlocks > c.MaxSharedReadBlocks {
			t.Fatalf("%s shared read blocks %d > %d", c.Name, result.SharedReadBlocks, c.MaxSharedReadBlocks)
		}
		for _, rel := range c.ForbidSeqScan {
			if result.SeqScans[rel] {
				t.Fatalf("%s used sequential scan on %s", c.Name, rel)
			}
		}
		if c.ForbidSort && result.Sorted {
			t.Fatalf("%s used a Sort node (expected index-ordered)", c.Name)
		}
	}

	if path := os.Getenv("QUERY_PERF_REPORT"); path != "" {
		writePerfReport(t, path, results)
	}
}

type perfCase struct {
	Name                string
	SQL                 string
	Args                []any
	ForbidSeqScan       []string
	ForbidSort          bool
	MaxExecutionMS      float64
	MaxSharedReadBlocks int64
}

type perfResult struct {
	Name              string          `json:"name"`
	Scale             int             `json:"scale"`
	ExecutionMS       float64         `json:"execution_ms"`
	PlanningMS        float64         `json:"planning_ms"`
	SharedReadBlocks  int64           `json:"shared_read_blocks"`
	SharedHitBlocks   int64           `json:"shared_hit_blocks"`
	TempReadBlocks    int64           `json:"temp_read_blocks"`
	TempWrittenBlocks int64           `json:"temp_written_blocks"`
	SeqScans          map[string]bool `json:"seq_scans"`
	Sorted            bool            `json:"sorted"`
}

type explainJSON struct {
	Plan          planJSON `json:"Plan"`
	PlanningTime  float64  `json:"Planning Time"`
	ExecutionTime float64  `json:"Execution Time"`
}

type planJSON struct {
	NodeType          string     `json:"Node Type"`
	RelationName      string     `json:"Relation Name"`
	SharedReadBlocks  int64      `json:"Shared Read Blocks"`
	SharedHitBlocks   int64      `json:"Shared Hit Blocks"`
	TempReadBlocks    int64      `json:"Temp Read Blocks"`
	TempWrittenBlocks int64      `json:"Temp Written Blocks"`
	Plans             []planJSON `json:"Plans"`
}

type copyExecDB interface {
	CopyFrom(context.Context, pgx.Identifier, []string, pgx.CopyFromSource) (int64, error)
	Exec(context.Context, string, ...interface{}) (pgconn.CommandTag, error)
}

type txDB interface {
	Begin(context.Context) (pgx.Tx, error)
}

func seedPerfData(t *testing.T, ctx context.Context, pool copyExecDB, rootID string, scale int) {
	t.Helper()
	now := time.Now().UTC()
	if _, err := pool.Exec(ctx, `INSERT INTO profiles.permission_groups (id, persona) VALUES ($1::uuid, 'root')`, rootID); err != nil {
		t.Fatalf("insert root group: %v", err)
	}

	// 2% of users soft-deleted in the past, so UsersPurgeCandidates has rows to
	// walk via the partial users_deleted_at_idx.
	copyUsers := pgx.CopyFromSlice(scale, func(i int) ([]any, error) {
		var deletedAt any
		if i%50 == 0 {
			// Distinct timestamps so ORDER BY deleted_at + LIMIT can stop early on
			// the (deleted_at, id) index instead of sorting the whole match set.
			deletedAt = now.Add(-time.Duration(i+1) * time.Hour)
		}
		return []any{
			perfUserID(i), perfEmail(i), perfUsername(i), true, now, now, deletedAt,
		}, nil
	})
	if n, err := pool.CopyFrom(ctx, pgx.Identifier{"profiles", "users"},
		[]string{"id", "email", "username", "email_verified", "created_at", "updated_at", "deleted_at"}, copyUsers); err != nil || int(n) != scale {
		t.Fatalf("copy users n=%d err=%v", n, err)
	}

	// One active session per user; previous_token_hash populated so the partial
	// refresh_sessions_prev_hash_active index has rows to probe.
	copySessions := pgx.CopyFromSlice(scale, func(i int) ([]any, error) {
		return []any{
			perfSessionID(i), perfFamilyID(i), perfUserID(i), perfIssuer,
			tokenHash(i), prevHash(i), now.Add(24 * time.Hour), []string{"pwd"},
		}, nil
	})
	if n, err := pool.CopyFrom(ctx, pgx.Identifier{"profiles", "refresh_sessions"},
		[]string{"id", "family_id", "user_id", "issuer", "current_token_hash", "previous_token_hash", "expires_at", "auth_methods"}, copySessions); err != nil || int(n) != scale {
		t.Fatalf("copy sessions n=%d err=%v", n, err)
	}

	// Fat user: many active sessions with distinct last_used_at, so the per-user
	// access path (list / evict-oldest) faces real fan-out and ordering.
	copyFat := pgx.CopyFromSlice(perfFat, func(j int) ([]any, error) {
		return []any{
			fmt.Sprintf("21000000-0000-4000-8000-%012x", j),
			fmt.Sprintf("31000000-0000-4000-8000-%012x", j),
			perfUserID(perfFatUser), perfIssuer,
			[]byte(fmt.Sprintf("fattoken-%012x", j)), []byte(fmt.Sprintf("fatprev-%012x", j)),
			now.Add(24 * time.Hour), now.Add(-time.Duration(j) * time.Minute), []string{"pwd"},
		}, nil
	})
	if n, err := pool.CopyFrom(ctx, pgx.Identifier{"profiles", "refresh_sessions"},
		[]string{"id", "family_id", "user_id", "issuer", "current_token_hash", "previous_token_hash", "expires_at", "last_used_at", "auth_methods"}, copyFat); err != nil || int(n) != perfFat {
		t.Fatalf("copy fat sessions n=%d err=%v", n, err)
	}

	copyMemberships := pgx.CopyFromSlice(scale, func(i int) ([]any, error) {
		return []any{rootID, perfUserID(i), "owner", now, now}, nil
	})
	if n, err := pool.CopyFrom(ctx, pgx.Identifier{"profiles", "group_user_roles"},
		[]string{"permission_group_id", "user_id", "role", "created_at", "updated_at"}, copyMemberships); err != nil || int(n) != scale {
		t.Fatalf("copy memberships n=%d err=%v", n, err)
	}

	// One provider link per user, spread across perfIssuers issuers: unique
	// (issuer, subject) for ProviderLinkByIssuer; (user_id, provider_slug) for
	// UserProviderSlugs. The issuer spread exercises per-issuer skip-scan cost.
	copyProviders := pgx.CopyFromSlice(scale, func(i int) ([]any, error) {
		return []any{
			perfProviderID(i), perfUserID(i), perfIdpIssuer(i), perfSubject(i), "github", perfIdpEmail(i),
		}, nil
	})
	if n, err := pool.CopyFrom(ctx, pgx.Identifier{"profiles", "user_providers"},
		[]string{"id", "user_id", "issuer", "subject", "provider_slug", "email_at_provider"}, copyProviders); err != nil || int(n) != scale {
		t.Fatalf("copy providers n=%d err=%v", n, err)
	}

	for _, table := range []string{
		"profiles.users", "profiles.refresh_sessions", "profiles.group_user_roles",
		"profiles.user_providers",
	} {
		// VACUUM, not just ANALYZE, so the visibility map is set: covering indexes
		// like users_deleted_at_idx (deleted_at, id) then serve true index-only
		// scans, the way they do on a live autovacuumed table. Without it an
		// index-only-eligible scan still does one heap visibility fetch per row,
		// inflating the buffer counts this test budgets against (e.g. the 100
		// purge candidates are scattered ~one per 50 heap rows).
		if _, err := pool.Exec(ctx, "VACUUM (ANALYZE) "+table); err != nil {
			t.Fatalf("vacuum analyze %s: %v", table, err)
		}
	}
}

// explain runs EXPLAIN (ANALYZE, BUFFERS) on the REAL query text inside a
// transaction that is always rolled back, so write queries are planned and timed
// against the seed without persisting their effects.
func explain(t *testing.T, ctx context.Context, pool txDB, scale int, c perfCase) perfResult {
	t.Helper()
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin %s: %v", c.Name, err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	var raw []byte
	args := append([]any{}, c.Args...)
	if err := tx.QueryRow(ctx, "EXPLAIN (ANALYZE, BUFFERS, FORMAT JSON) "+stripQueryHeader(c.SQL), args...).Scan(&raw); err != nil {
		t.Fatalf("explain %s: %v", c.Name, err)
	}
	var plans []explainJSON
	if err := json.Unmarshal(raw, &plans); err != nil {
		t.Fatalf("parse explain %s: %v", c.Name, err)
	}
	if len(plans) != 1 {
		t.Fatalf("parse explain %s: got %d plans", c.Name, len(plans))
	}
	result := perfResult{
		Name: c.Name, Scale: scale, PlanningMS: plans[0].PlanningTime,
		ExecutionMS: plans[0].ExecutionTime, SeqScans: map[string]bool{},
	}
	collectPlan(plans[0].Plan, &result)
	return result
}

// stripQueryHeader drops the leading sqlc `-- name: ... :kind` comment (and any
// blank lines) so EXPLAIN sees only the statement.
func stripQueryHeader(sql string) string {
	lines := strings.Split(sql, "\n")
	i := 0
	for i < len(lines) {
		trimmed := strings.TrimSpace(lines[i])
		if trimmed == "" || strings.HasPrefix(trimmed, "--") {
			i++
			continue
		}
		break
	}
	return strings.Join(lines[i:], "\n")
}

func collectPlan(p planJSON, r *perfResult) {
	r.SharedReadBlocks += p.SharedReadBlocks
	r.SharedHitBlocks += p.SharedHitBlocks
	r.TempReadBlocks += p.TempReadBlocks
	r.TempWrittenBlocks += p.TempWrittenBlocks
	if p.NodeType == "Seq Scan" && p.RelationName != "" {
		r.SeqScans[p.RelationName] = true
	}
	if p.NodeType == "Sort" || p.NodeType == "Incremental Sort" {
		r.Sorted = true
	}
	for _, child := range p.Plans {
		collectPlan(child, r)
	}
}

func writePerfReport(t *testing.T, path string, results []perfResult) {
	t.Helper()
	data, err := json.MarshalIndent(results, "", "  ")
	if err != nil {
		t.Fatalf("marshal perf report: %v", err)
	}
	if err := os.WriteFile(path, append(data, '\n'), 0o644); err != nil {
		t.Fatalf("write perf report: %v", err)
	}
}

func envInt(key string, fallback int) int {
	value := os.Getenv(key)
	if value == "" {
		return fallback
	}
	n, err := strconv.Atoi(value)
	if err != nil || n <= 0 {
		return fallback
	}
	return n
}

func perfUserID(i int) string     { return fmt.Sprintf("10000000-0000-4000-8000-%012x", i) }
func perfSessionID(i int) string  { return fmt.Sprintf("20000000-0000-4000-8000-%012x", i) }
func perfFamilyID(i int) string   { return fmt.Sprintf("30000000-0000-4000-8000-%012x", i) }
func perfProviderID(i int) string { return fmt.Sprintf("40000000-0000-4000-8000-%012x", i) }
func tokenHash(i int) []byte      { return []byte(fmt.Sprintf("token-%012x", i)) }
func prevHash(i int) []byte       { return []byte(fmt.Sprintf("prev-%012x", i)) }
func perfEmail(i int) string      { return fmt.Sprintf("user%06d@example.test", i) }
func perfUsername(i int) string   { return fmt.Sprintf("user%06d", i) }
func perfSubject(i int) string    { return fmt.Sprintf("sub-%06d", i) }
func perfIdpEmail(i int) string   { return fmt.Sprintf("idp%06d@example.test", i) }
func perfIdpIssuer(i int) string  { return fmt.Sprintf("https://perf-idp-%d.example", i%perfIssuers) }
