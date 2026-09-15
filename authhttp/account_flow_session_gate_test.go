package authhttp

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/stretchr/testify/require"
)

// completeWhileRevoking proves the revocation waits for an in-flight session
// completion, then returns its HTTP result for the scenario's token assertions.
// The caller must also check the intended final state: source-only revocation
// permits this already-authorized session; revoke-all must revoke it as well.
func (f *accountFlow) completeWhileRevoking(userID string, complete func() flowResponse, revoke func(context.Context) error) flowResponse {
	t := f.t
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	// An independent control connection avoids occupying the application pool,
	// including CI's four-connection pool. It owns both the gate and observation.
	control, err := pgx.ConnectConfig(ctx, f.service.svc.Postgres().Config().ConnConfig.Copy())
	require.NoError(t, err)
	defer control.Close(context.Background())
	var pid int32
	require.NoError(t, control.QueryRow(ctx, `SELECT pg_backend_pid(), $1::uuid::text`, userID).Scan(&pid, &userID))
	const gateNamespace = 7363189
	name := fmt.Sprintf("flow_session_gate_%d", pid)
	function := pgx.Identifier{"profiles", name}.Sanitize()
	trigger := pgx.Identifier{name}.Sanitize()
	gateHeld := false
	// Always release the gate before dropping its DDL, including assertion
	// failures; otherwise an INSERT can retain a table lock and stall cleanup.
	defer func() {
		cleanup, stop := context.WithTimeout(context.Background(), 10*time.Second)
		defer stop()
		if gateHeld {
			_, unlockErr := control.Exec(cleanup, `SELECT pg_advisory_unlock($1::int, $2::int)`, gateNamespace, pid)
			if unlockErr != nil {
				t.Errorf("release session gate: %v", unlockErr)
			}
		}
		_, dropErr := control.Exec(cleanup, "DROP TRIGGER IF EXISTS "+trigger+" ON profiles.refresh_sessions; DROP FUNCTION IF EXISTS "+function+"()")
		if dropErr != nil {
			t.Errorf("remove session gate: %v", dropErr)
		}
	}()
	_, err = control.Exec(ctx, "CREATE FUNCTION "+function+`() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF NEW.user_id::text = TG_ARGV[0] THEN
    PERFORM pg_advisory_xact_lock(7363189, TG_ARGV[1]::int);
  END IF;
  RETURN NEW;
END $$`)
	require.NoError(t, err)
	// userID was canonicalized by PostgreSQL above; only this account is paused.
	_, err = control.Exec(ctx, fmt.Sprintf("CREATE TRIGGER %s BEFORE INSERT ON profiles.refresh_sessions FOR EACH ROW EXECUTE FUNCTION %s('%s', '%d')", trigger, function, userID, pid))
	require.NoError(t, err)
	_, err = control.Exec(ctx, `SELECT pg_advisory_lock($1::int, $2::int)`, gateNamespace, pid)
	require.NoError(t, err)
	gateHeld = true

	completed := make(chan flowResponse, 1)
	go func() {
		defer close(completed)
		completed <- complete()
	}()
	var revoked chan error
	// Observe actual lock ownership, not query text (which depends on DB-role
	// visibility). All assertions stay on the test goroutine. Early completion
	// fails immediately instead of being mistaken for a scheduling delay.
	waitForBackend := func(stage, query string, args ...any) int32 {
		ticker := time.NewTicker(10 * time.Millisecond)
		defer ticker.Stop()
		for {
			var backend int32
			require.NoError(t, control.QueryRow(ctx, query, args...).Scan(&backend), stage)
			if backend != 0 {
				return backend
			}
			select {
			case response, ok := <-completed:
				t.Fatalf("%s: completion returned before gate release (response=%t, status=%d, body=%s)", stage, ok, response.status, response.raw)
			case revokeErr, ok := <-revoked:
				t.Fatalf("%s: revocation did not wait for completion (result=%t, error=%v)", stage, ok, revokeErr)
			case <-ctx.Done():
				t.Fatalf("%s: %v", stage, ctx.Err())
			case <-ticker.C:
			}
		}
	}
	insertPID := waitForBackend("session INSERT waiting on gate", `SELECT COALESCE((
  SELECT pid FROM pg_locks WHERE locktype='advisory' AND NOT granted
  AND database=(SELECT oid FROM pg_database WHERE datname=current_database())
  AND classid=$1::oid AND objid=$2::oid AND objsubid=2 LIMIT 1
), 0)`, gateNamespace, pid)
	revoked = make(chan error, 1)
	go func() {
		defer close(revoked)
		revoked <- revoke(ctx)
	}()
	waitForBackend("revocation waiting on completion", `SELECT COALESCE((
  SELECT pid FROM pg_locks WHERE NOT granted AND $1::int=ANY(pg_blocking_pids(pid)) LIMIT 1
), 0)`, insertPID)
	var unlocked bool
	require.NoError(t, control.QueryRow(ctx, `SELECT pg_advisory_unlock($1::int, $2::int)`, gateNamespace, pid).Scan(&unlocked))
	require.True(t, unlocked)
	gateHeld = false
	var response flowResponse
	select {
	case result, ok := <-completed:
		require.True(t, ok, "completion exited without an HTTP response")
		response = result
	case <-ctx.Done():
		t.Fatalf("session completion after gate release: %v", ctx.Err())
	}
	select {
	case revokeErr, ok := <-revoked:
		require.True(t, ok, "revocation exited without a result")
		require.NoError(t, revokeErr)
	case <-ctx.Done():
		t.Fatalf("revocation after gate release: %v", ctx.Err())
	}
	return response
}
