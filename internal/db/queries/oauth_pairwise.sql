-- Pairwise subjects of group OAuth clients (#487).

-- name: OAuthPairwiseSubject :one
SELECT subject::text FROM oauth_pairwise_subjects
WHERE permission_group_id = sqlc.arg(group_id)::uuid AND user_id = sqlc.arg(user_id)::uuid;

-- name: OAuthPairwiseSubjectCreate :one
-- Gives the user a subject at the group, or answers the one a concurrent
-- first use gave.
INSERT INTO oauth_pairwise_subjects (permission_group_id, user_id)
VALUES (sqlc.arg(group_id)::uuid, sqlc.arg(user_id)::uuid)
ON CONFLICT (permission_group_id, user_id) DO UPDATE SET subject = oauth_pairwise_subjects.subject
RETURNING subject::text;

-- name: OAuthPairwiseSubjectUser :one
-- The user a subject at the group stands for.
SELECT user_id::text FROM oauth_pairwise_subjects
WHERE permission_group_id = sqlc.arg(group_id)::uuid AND subject = sqlc.arg(subject)::uuid;
