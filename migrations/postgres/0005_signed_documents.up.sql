-- parent: 4 sha256:d0cbb69cfd643ed065d27a6d2301ab09eeb363ca1f3c4af3270b387eb06fcc42
-- ak#260: AuthKit-owned signed-document store.
--
-- One row per published immutable document (documents.SignedDocument). The
-- digest is content-addressed over the exact signed payload bytes, so the
-- payload and type are immutable for a digest; only compact_jws may be
-- replaced, and only by a re-signature of the SAME payload (signing-key
-- rotation repair). That invariant is enforced by the guarded upsert in
-- internal/db/queries/signed_documents.sql, not by application convention.
CREATE TABLE IF NOT EXISTS profiles.signed_documents (
  digest         text PRIMARY KEY,
  document_type  text NOT NULL,
  compact_jws    text NOT NULL,
  signed_payload bytea NOT NULL,
  created_at     timestamptz NOT NULL DEFAULT now(),
  updated_at     timestamptz NOT NULL DEFAULT now()
);

COMMENT ON TABLE profiles.signed_documents IS
  'AuthKit-published immutable signed documents (ak#260), served at /.well-known/authkit/documents/{digest}. Digest = sha256 over signed_payload; compact_jws may be re-signed on key rotation, payload/type never change.';
