package embedded

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// requireSameRiverDatabase proves the actual cluster/database before enabling
// transactional producers. Schema pool copies, different roles and connection
// aliases are normal. Neither connection strings nor pool pointers prove that
// two distinct pools will expose committed jobs to the same fleet.
func requireSameRiverDatabase(ctx context.Context, producer, worker *pgxpool.Pool) (err error) {
	if ctx == nil {
		return errors.New("authkit: River database identity requires a context")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if producer == nil || worker == nil {
		return errors.New("authkit: River binding requires both PostgreSQL pools")
	}
	if producer == worker {
		return nil
	} // also safe with its only connection borrowed
	var nonce [16]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return err
	}
	var keys [4]int32
	for i := range keys {
		keys[i] = int32(binary.BigEndian.Uint32(nonce[i*4:]) & 0x7fffffff)
	}
	if keys[0] == keys[2] && keys[1] == keys[3] {
		keys[3] ^= 1
	}
	conn, err := producer.Acquire(ctx)
	if err != nil {
		return err
	}
	defer conn.Release()
	tx, err := conn.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() {
		cleanup, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if rollbackErr := tx.Rollback(cleanup); rollbackErr != nil {
			err = errors.Join(err, fmt.Errorf("release River database witness: %w", rollbackErr))
		}
	}()
	var pid int32
	var first, second bool
	err = tx.QueryRow(ctx, `SELECT pg_catalog.pg_backend_pid(),pg_catalog.pg_try_advisory_xact_lock($1::integer,$2::integer),pg_catalog.pg_try_advisory_xact_lock($3::integer,$4::integer)`, keys[0], keys[1], keys[2], keys[3]).Scan(&pid, &first, &second)
	if err != nil {
		return err
	}
	if !first || !second {
		return errors.New("authkit: River database witness keys are already held")
	}
	var same bool
	err = worker.QueryRow(ctx, `SELECT pg_catalog.count(*)=2 FROM pg_catalog.pg_locks
 WHERE locktype='advisory' AND pid=$1::integer AND granted AND mode='ExclusiveLock' AND objsubid=2
 AND database=(SELECT oid FROM pg_catalog.pg_database WHERE datname=pg_catalog.current_database())
 AND ((classid=$2::bigint::pg_catalog.oid AND objid=$3::bigint::pg_catalog.oid)
 OR (classid=$4::bigint::pg_catalog.oid AND objid=$5::bigint::pg_catalog.oid))`, pid, int64(keys[0]), int64(keys[1]), int64(keys[2]), int64(keys[3])).Scan(&same)
	if err != nil {
		return err
	}
	if !same {
		return errors.New("authkit: host River and account storage must use the same PostgreSQL database; use managed AuthKit River for a separate database")
	}
	return ctx.Err()
}
