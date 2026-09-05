-- parent: 6 sha256:ba56d2c3572f24b403da4a3b4fb187662b17e215932fca8586fb70228c1c6f23
-- ak#274: a bounded GRACE WINDOW on refresh-token rotation.
--
-- Rotation is single-use: the presented token becomes previous_token_hash and a
-- fresh one becomes current. A second holder of the SAME token — a shared
-- credential file, a retried request, a response lost in flight — therefore
-- presents a token that is already `previous`, which reuse detection reads as
-- theft and answers with a family-wide revoke. That is the mechanism that
-- revoked 737 of 740 sessions on one box in a single incident.
--
-- The fix re-delivers the token's OWN successor for a short window instead of
-- minting a second chain, so N racers converge on one credential. Doing that
-- needs the successor recoverable, and recovering it must not weaken at-rest
-- hashing: previous_successor_sealed holds the successor XOR-sealed under a
-- keystream derived from the PREDECESSOR token, which the database never
-- stores. A dump yields the seal and a SHA-256 of the predecessor and unseals
-- nothing; only a caller already holding the predecessor — already a
-- credential — can open it, so the grace path grants no capability the
-- presented token did not already carry.
--
-- previous_rotated_at bounds the window. Both are NULL until the next rotation
-- of an existing session, which simply means no grace for that one exchange.
ALTER TABLE profiles.refresh_sessions
  ADD COLUMN IF NOT EXISTS previous_successor_sealed bytea,
  ADD COLUMN IF NOT EXISTS previous_rotated_at timestamptz;

COMMENT ON COLUMN profiles.refresh_sessions.previous_successor_sealed IS
  'Successor refresh token, XOR-sealed under SHA-256(predecessor || domain separator). Readable only by a caller holding the predecessor token; the database alone cannot unseal it (ak#274).';

COMMENT ON COLUMN profiles.refresh_sessions.previous_rotated_at IS
  'When previous_token_hash last became previous. Bounds the rotation grace window (ak#274).';
