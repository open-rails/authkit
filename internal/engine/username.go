package engine

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"math/big"
	"strings"

	"github.com/jackc/pgx/v5"
	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/internal/db"
)

const generatedUsernameAttempts = 100

// GenerateUsername returns an unreserved, currently available username from
// the app's name pool plus exactly three cryptographically random digits.
// Assignment still checks the database's unique constraint.
func (s *Engine) GenerateUsername(ctx context.Context) (string, error) {
	return s.generateUsername(ctx, s.q)
}

func (s *Engine) generateUsername(ctx context.Context, q *db.Queries) (string, error) {
	pool := s.cfg.Username.RandomNames
	if pool == nil {
		if s.cfg.Username.MaxLength < 4 {
			return "", errors.New("authkit: generated usernames require MaxLength >= 4")
		}
		base := "user"[:min(4, s.cfg.Username.MaxLength-3)]
		for len(base)+3 < s.cfg.Username.MinLength {
			base += "_"
		}
		pool = []string{base}
	}
	for range generatedUsernameAttempts {
		choice, err := rand.Int(rand.Reader, big.NewInt(int64(len(pool))))
		if err != nil {
			return "", err
		}
		suffix, err := rand.Int(rand.Reader, big.NewInt(1000))
		if err != nil {
			return "", err
		}
		candidate := fmt.Sprintf("%s%03d", strings.ToLower(pool[choice.Int64()]), suffix.Int64())
		if err := s.checkUsername(ctx, q, candidate); err != nil {
			if errors.Is(err, iam.ErrUsernameInUse) {
				continue
			}
			return "", err
		}
		return candidate, nil
	}
	return "", fmt.Errorf("generate username: %w", iam.ErrUsernameInUse)
}

// importGeneratedUser keeps the enclosing group mutation atomic while retrying
// a generated-name race. The caller already holds its authority transaction.
func (s *Engine) importGeneratedUser(ctx context.Context, target db.DBTX, in newAccount) (*db.User, error) {
	tx, ok := target.(pgx.Tx)
	if !ok {
		return nil, errors.New("authkit: generated user import requires a transaction")
	}
	q := db.New(tx)
	for range generatedUsernameAttempts {
		name, err := s.generateUsername(ctx, q)
		if err != nil {
			return nil, err
		}
		in.Username = name
		sp, err := tx.Begin(ctx)
		if err != nil {
			return nil, err
		}
		user, err := s.importUser(ctx, db.New(sp), in)
		if err == nil {
			return user, sp.Commit(ctx)
		}
		if rollbackErr := sp.Rollback(ctx); rollbackErr != nil {
			return nil, rollbackErr
		}
		if !errors.Is(mapUserUniqueViolation(err), iam.ErrUsernameInUse) {
			return nil, mapUserUniqueViolation(err)
		}
	}
	return nil, iam.ErrUsernameInUse
}
