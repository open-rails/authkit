package engine

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/open-rails/authkit/internal/db"
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
	held, err := db.New(tx).RiverIdentityProbeLock(ctx, db.RiverIdentityProbeLockParams{Key1: keys[0], Key2: keys[1], Key3: keys[2], Key4: keys[3]})
	if err != nil {
		return err
	}
	if !held.First || !held.Second {
		return errors.New("authkit: River database witness keys are already held")
	}
	same, err := db.New(worker).RiverIdentityProbeSeen(ctx, db.RiverIdentityProbeSeenParams{
		Pid: held.Pid, Class1: int64(keys[0]), Obj1: int64(keys[1]), Class2: int64(keys[2]), Obj2: int64(keys[3]),
	})
	if err != nil {
		return err
	}
	if !same {
		return errors.New("authkit: host River and account storage must use the same PostgreSQL database; use managed AuthKit River for a separate database")
	}
	return ctx.Err()
}
