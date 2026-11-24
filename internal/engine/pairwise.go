package engine

// Pairwise subjects (#487, OIDC Core §8.1). With GroupClients.PairwiseSubjects
// a group's clients know a user by a random subject of that group alone
// (oauth_pairwise_subjects), and a sign-in by a hash of its session with the
// group: groups cannot join their users, nor a sign-in they share. Every
// token a client can read carries them, access tokens too (RFC 9068 §6), and
// only this deployment maps them back.

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"strings"

	"github.com/jackc/pgx/v5"

	"github.com/open-rails/authkit/internal/authflow"
	"github.com/open-rails/authkit/internal/db"
)

// errUnknownSubject is a pairwise subject or sid that names no user or
// sign-in of the client's group.
var errUnknownSubject = errors.New("authkit: unknown pairwise subject")

// pairwiseGroup is the group client's subjects are pairwise in: its own,
// with GroupClients.PairwiseSubjects; "" for the public user id.
func (s *Engine) pairwiseGroup(client authflow.OAuthClient) string {
	if !s.cfg.AuthorizationServer.GroupClients.PairwiseSubjects || client.Group == nil {
		return ""
	}
	return client.Group.GroupID
}

// clientSubject is the sub and sid client knows userID and sessionID by.
func (s *Engine) clientSubject(ctx context.Context, client authflow.OAuthClient, userID, sessionID string) (sub, sid string, err error) {
	group := s.pairwiseGroup(client)
	if group == "" {
		return userID, sessionID, nil
	}
	if sub, err = pairwiseSubject(ctx, s.q, group, userID); err != nil {
		return "", "", err
	}
	return sub, pairwiseSID(group, sessionID), nil
}

// pairwiseSubject is userID's subject at group, created on first use.
func pairwiseSubject(ctx context.Context, q *db.Queries, group, userID string) (string, error) {
	sub, err := q.OAuthPairwiseSubject(ctx, db.OAuthPairwiseSubjectParams{GroupID: group, UserID: userID})
	if errors.Is(err, pgx.ErrNoRows) {
		sub, err = q.OAuthPairwiseSubjectCreate(ctx, db.OAuthPairwiseSubjectCreateParams{GroupID: group, UserID: userID})
	}
	return sub, err
}

// pairwiseSID is the sid a group's clients know a session by: not reversible
// without the session id, which no client sees.
func pairwiseSID(group, sessionID string) string {
	if sessionID == "" {
		return ""
	}
	sum := sha256.Sum256([]byte("authkit pairwise sid\x00" + group + "\x00" + sessionID))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// clientAccount is the user and session the sub and sid of a token client
// holds stand for: themselves for a public subject. errUnknownSubject when
// they name none; a sid of no live session of the user resolves to none.
func (s *Engine) clientAccount(ctx context.Context, client authflow.OAuthClient, sub, sid string) (userID, sessionID string, err error) {
	group := s.pairwiseGroup(client)
	if group == "" {
		return sub, sid, nil
	}
	if !isUUID(sub) {
		return "", "", errUnknownSubject
	}
	userID, err = s.q.OAuthPairwiseSubjectUser(ctx, db.OAuthPairwiseSubjectUserParams{GroupID: group, Subject: strings.ToLower(sub)})
	if errors.Is(err, pgx.ErrNoRows) {
		return "", "", errUnknownSubject
	}
	if err != nil || sid == "" {
		return userID, "", err
	}
	sessions, err := s.q.SessionsListByUser(ctx, db.SessionsListByUserParams{UserID: userID, Issuer: s.cfg.Token.Issuer})
	if err != nil {
		return "", "", err
	}
	for _, session := range sessions {
		if pairwiseSID(group, session.ID) == sid {
			return userID, session.ID, nil
		}
	}
	return userID, "", errUnknownSubject
}
