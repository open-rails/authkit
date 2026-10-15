package engine

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5"
	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/internal/db"
	"github.com/open-rails/authkit/userinfo"
)

// UserInfoTx reads the selected native directory in the host transaction.
func (s *Engine) UserInfoTx(ctx context.Context, host pgx.Tx, ids []string) (map[string]userinfo.User, error) {
	if _, err := s.tenantID(ctx); err != nil {
		return nil, err
	}
	return s.userInfoTransaction(ctx, host, func(tx pgx.Tx) (map[string]userinfo.User, error) {
		return s.userInfo(ctx, db.New(tx), ids)
	})
}

// RemoteUserInfoTx resolves the live group and reads its remote directory in
// the same transaction. It never borrows another pool connection.
func (s *Engine) RemoteUserInfoTx(ctx context.Context, host pgx.Tx, ref iam.GroupRef, issuer string, ids []string) (map[string]userinfo.User, error) {
	return s.userInfoTransaction(ctx, host, func(tx pgx.Tx) (map[string]userinfo.User, error) {
		group, err := s.resolveGroup(ctx, s.groupStoreFor(tx), ref)
		if errors.Is(err, iam.ErrGroupNotFound) {
			return map[string]userinfo.User{}, nil
		}
		if err != nil {
			return nil, err
		}
		ctx, _, err = s.remoteLookupGroupContext(ctx, group)
		if err != nil {
			return nil, err
		}
		return remoteUserInfoFrom(ctx, db.New(tx), group.ID, issuer, ids)
	})
}

func (s *Engine) userInfoTransaction(ctx context.Context, host pgx.Tx, read func(pgx.Tx) (map[string]userinfo.User, error)) (map[string]userinfo.User, error) {
	if err := s.requirePG(); err != nil {
		return nil, err
	}
	if host == nil {
		return nil, errors.New("authkit: directory GetTx requires a transaction")
	}
	tx, err := s.joinHostTransaction(ctx, host)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(context.WithoutCancel(ctx))
	users, err := read(tx)
	if err != nil {
		return nil, err
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	return users, nil
}
