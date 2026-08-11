-- ak#260: AuthKit-owned signed-document store (documents.Service).

-- SaveSignedDocument persists an immutable signed document. The upsert is the
-- digest-immutability guard: a conflicting digest only updates compact_jws
-- when the stored type AND exact payload bytes match (a key-rotation
-- re-signature of the same document); any other collision affects 0 rows and
-- the caller fails loudly.
-- name: SaveSignedDocument :execrows
INSERT INTO profiles.signed_documents (digest, document_type, compact_jws, signed_payload)
VALUES (sqlc.arg(digest), sqlc.arg(document_type), sqlc.arg(compact_jws), sqlc.arg(signed_payload))
ON CONFLICT (digest) DO UPDATE
SET compact_jws = excluded.compact_jws,
    updated_at = now()
WHERE profiles.signed_documents.document_type = excluded.document_type
  AND profiles.signed_documents.signed_payload = excluded.signed_payload;

-- name: LookupSignedDocument :one
SELECT document_type, compact_jws, signed_payload
FROM profiles.signed_documents
WHERE digest = sqlc.arg(digest);
