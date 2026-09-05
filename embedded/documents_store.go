package embedded

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"

	"github.com/open-rails/authkit/documents"
	"github.com/open-rails/authkit/internal/db"
)

// DocumentStore returns the engine-owned documents.Store over the
// signed_documents table (migration 0005). Digest immutability is enforced by
// the guarded upsert: an existing digest only ever accepts a compact-JWS
// replacement for the SAME type + payload bytes.
func (s *Service) DocumentStore() documents.Store {
	return documentStore{q: s.q}
}

type documentStore struct {
	q *db.Queries
}

func (d documentStore) SaveDocument(ctx context.Context, document documents.SignedDocument) error {
	if err := document.Reference.Validate(); err != nil {
		return err
	}
	if documents.Digest(document.SignedPayload) != document.Reference.Digest {
		return documents.ErrDigestMismatch
	}
	rows, err := d.q.SaveSignedDocument(ctx, db.SaveSignedDocumentParams{
		Digest:        document.Reference.Digest,
		DocumentType:  document.Reference.Type,
		CompactJws:    document.CompactJWS,
		SignedPayload: document.SignedPayload,
	})
	if err != nil {
		return fmt.Errorf("persist immutable document: %w", err)
	}
	if rows != 1 {
		return documents.ErrDigestCollision
	}
	return nil
}

func (d documentStore) Lookup(ctx context.Context, digest string) (documents.SignedDocument, error) {
	if err := documents.ValidateDigest(digest); err != nil {
		return documents.SignedDocument{}, documents.ErrNotFound
	}
	row, err := d.q.LookupSignedDocument(ctx, digest)
	if errors.Is(err, pgx.ErrNoRows) {
		return documents.SignedDocument{}, documents.ErrNotFound
	}
	if err != nil {
		return documents.SignedDocument{}, fmt.Errorf("lookup document: %w", err)
	}
	return documents.SignedDocument{
		CompactJWS:    row.CompactJws,
		Reference:     documents.Reference{Type: row.DocumentType, Digest: digest},
		SignedPayload: row.SignedPayload,
	}, nil
}
