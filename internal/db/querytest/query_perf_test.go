package querytest

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/open-rails/authkit/internal/testdb"
)

func TestQueryPerformance(t *testing.T) {
	pg := testdb.ScratchPostgres(t)
	ctx := context.Background()
	scale := envInt("QUERY_PERF_SCALE", 100000)

	rootID := fixedUUID(9000000)
	seedPerfData(t, ctx, pg.Pool, rootID, scale)

	cases := []perfCase{
		{
			Name: "user_by_email", MaxExecutionMS: 50, MaxSharedReadBlocks: 16,
			SQL:           `SELECT id FROM profiles.users WHERE email = lower($1::text)::citext`,
			Args:          []any{fmt.Sprintf("user%06d@example.test", scale-1)},
			ForbidSeqScan: []string{"users"},
		},
		{
			Name: "session_by_current_hash", MaxExecutionMS: 50, MaxSharedReadBlocks: 16,
			SQL:           `SELECT id FROM profiles.refresh_sessions WHERE current_token_hash = $1 AND issuer = $2 AND revoked_at IS NULL AND (expires_at IS NULL OR expires_at > now())`,
			Args:          []any{tokenHash(scale - 1), "https://perf.example"},
			ForbidSeqScan: []string{"refresh_sessions"},
		},
		{
			Name: "sessions_by_user", MaxExecutionMS: 75, MaxSharedReadBlocks: 32,
			SQL:           `SELECT id FROM profiles.refresh_sessions WHERE user_id = $1::uuid AND issuer = $2 AND revoked_at IS NULL`,
			Args:          []any{perfUserID(scale - 1), "https://perf.example"},
			ForbidSeqScan: []string{"refresh_sessions"},
		},
		{
			Name: "root_roles_for_page", MaxExecutionMS: 100, MaxSharedReadBlocks: 64,
			SQL:           `SELECT user_id::text, role FROM profiles.group_user_roles WHERE permission_group_id = $1::uuid AND user_id = ANY($2::uuid[]) AND deleted_at IS NULL`,
			Args:          []any{rootID, []string{perfUserID(1), perfUserID(scale / 2), perfUserID(scale - 1)}},
			ForbidSeqScan: []string{"group_user_roles"},
		},
	}

	results := make([]perfResult, 0, len(cases))
	for _, c := range cases {
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

func seedPerfData(t *testing.T, ctx context.Context, pool interface {
	CopyFrom(context.Context, pgx.Identifier, []string, pgx.CopyFromSource) (int64, error)
	Exec(context.Context, string, ...interface{}) (pgconn.CommandTag, error)
}, rootID string, scale int) {
	t.Helper()
	now := time.Now().UTC()
	if _, err := pool.Exec(ctx, `INSERT INTO profiles.permission_groups (id, persona) VALUES ($1::uuid, 'root')`, rootID); err != nil {
		t.Fatalf("insert root group: %v", err)
	}

	copyUsers := pgx.CopyFromSlice(scale, func(i int) ([]any, error) {
		return []any{
			perfUserID(i),
			fmt.Sprintf("user%06d@example.test", i),
			fmt.Sprintf("user%06d", i),
			true,
			now,
			now,
		}, nil
	})
	if n, err := pool.CopyFrom(ctx, pgx.Identifier{"profiles", "users"},
		[]string{"id", "email", "username", "email_verified", "created_at", "updated_at"}, copyUsers); err != nil || int(n) != scale {
		t.Fatalf("copy users n=%d err=%v", n, err)
	}

	copySessions := pgx.CopyFromSlice(scale, func(i int) ([]any, error) {
		return []any{
			perfSessionID(i),
			perfFamilyID(i),
			perfUserID(i),
			"https://perf.example",
			tokenHash(i),
			now.Add(24 * time.Hour),
			[]string{"pwd"},
		}, nil
	})
	if n, err := pool.CopyFrom(ctx, pgx.Identifier{"profiles", "refresh_sessions"},
		[]string{"id", "family_id", "user_id", "issuer", "current_token_hash", "expires_at", "auth_methods"}, copySessions); err != nil || int(n) != scale {
		t.Fatalf("copy sessions n=%d err=%v", n, err)
	}

	copyMemberships := pgx.CopyFromSlice(scale, func(i int) ([]any, error) {
		return []any{rootID, perfUserID(i), "owner", now, now}, nil
	})
	if n, err := pool.CopyFrom(ctx, pgx.Identifier{"profiles", "group_user_roles"},
		[]string{"permission_group_id", "user_id", "role", "created_at", "updated_at"}, copyMemberships); err != nil || int(n) != scale {
		t.Fatalf("copy memberships n=%d err=%v", n, err)
	}

	for _, table := range []string{"profiles.users", "profiles.refresh_sessions", "profiles.group_user_roles"} {
		if _, err := pool.Exec(ctx, "ANALYZE "+table); err != nil {
			t.Fatalf("analyze %s: %v", table, err)
		}
	}
}

func explain(t *testing.T, ctx context.Context, pool interface {
	QueryRow(context.Context, string, ...interface{}) pgx.Row
}, scale int, c perfCase) perfResult {
	t.Helper()
	var raw []byte
	args := append([]any{}, c.Args...)
	if err := pool.QueryRow(ctx, "EXPLAIN (ANALYZE, BUFFERS, FORMAT JSON) "+c.SQL, args...).Scan(&raw); err != nil {
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

func collectPlan(p planJSON, r *perfResult) {
	r.SharedReadBlocks += p.SharedReadBlocks
	r.SharedHitBlocks += p.SharedHitBlocks
	r.TempReadBlocks += p.TempReadBlocks
	r.TempWrittenBlocks += p.TempWrittenBlocks
	if p.NodeType == "Seq Scan" && p.RelationName != "" {
		r.SeqScans[p.RelationName] = true
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

func perfUserID(i int) string    { return fmt.Sprintf("10000000-0000-4000-8000-%012x", i) }
func perfSessionID(i int) string { return fmt.Sprintf("20000000-0000-4000-8000-%012x", i) }
func perfFamilyID(i int) string  { return fmt.Sprintf("30000000-0000-4000-8000-%012x", i) }
func tokenHash(i int) []byte     { return []byte(fmt.Sprintf("token-%012x", i)) }
