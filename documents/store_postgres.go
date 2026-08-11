package documents

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/open-rails/authkit/internal/db"
)

// postgresStore is the AuthKit-owned Store over the signed_documents table
// (migration 0004). Digest immutability is enforced by the guarded upsert:
// an existing digest only ever accepts a compact-JWS replacement for the SAME
// type + payload bytes.
type postgresStore struct {
	q *db.Queries
}

func newPostgresStore(pool *pgxpool.Pool, schema string) (*postgresStore, error) {
	if pool == nil {
		return nil, errors.New("authkit/documents: postgres pool is required")
	}
	return &postgresStore{q: db.New(db.ForSchema(pool, schema))}, nil
}

func (s *postgresStore) SaveDocument(ctx context.Context, document SignedDocument) error {
	if err := document.Reference.Validate(); err != nil {
		return err
	}
	if Digest(document.SignedPayload) != document.Reference.Digest {
		return ErrDigestMismatch
	}
	rows, err := s.q.SaveSignedDocument(ctx, db.SaveSignedDocumentParams{
		Digest:        document.Reference.Digest,
		DocumentType:  document.Reference.Type,
		CompactJws:    document.CompactJWS,
		SignedPayload: document.SignedPayload,
	})
	if err != nil {
		return fmt.Errorf("persist immutable document: %w", err)
	}
	if rows != 1 {
		return ErrDigestCollision
	}
	return nil
}

func (s *postgresStore) Lookup(ctx context.Context, digest string) (SignedDocument, error) {
	if err := ValidateDigest(digest); err != nil {
		return SignedDocument{}, ErrNotFound
	}
	row, err := s.q.LookupSignedDocument(ctx, digest)
	if errors.Is(err, pgx.ErrNoRows) {
		return SignedDocument{}, ErrNotFound
	}
	if err != nil {
		return SignedDocument{}, fmt.Errorf("lookup document: %w", err)
	}
	return SignedDocument{
		CompactJWS:    row.CompactJws,
		Reference:     Reference{Type: row.DocumentType, Digest: digest},
		SignedPayload: row.SignedPayload,
	}, nil
}
