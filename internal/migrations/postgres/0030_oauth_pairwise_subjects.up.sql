-- Pairwise subjects (#487, OIDC Core §8.1): with
-- AuthorizationServer.GroupClients.PairwiseSubjects, each group's clients
-- know a user by a random id of that group alone, so groups cannot join
-- their users. Only this deployment maps one back.
CREATE TABLE oauth_pairwise_subjects (
  permission_group_id uuid NOT NULL REFERENCES permission_groups(id) ON DELETE CASCADE,
  user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  subject uuid NOT NULL DEFAULT gen_random_uuid() CONSTRAINT oauth_pairwise_subjects_subject_key UNIQUE,
  created_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (permission_group_id, user_id)
);
CREATE INDEX oauth_pairwise_subjects_user_idx ON oauth_pairwise_subjects (user_id);
COMMENT ON TABLE oauth_pairwise_subjects IS
  'Each user''s pairwise subject at each group whose OAuth clients get pairwise subjects: random, stable for the pair, mapped back only here. Deleted with the user or the group.';
