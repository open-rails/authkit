package embedded

import (
	"context"
	"strings"

	authkit "github.com/open-rails/authkit"
	"github.com/open-rails/authkit/verify"
)

// A credential ceiling is retained separately from live grants: replacing or
// revoking a role must satisfy both, even if authority changes after verification.
type groupMutationActor struct {
	userID string
	remote *verify.Claims
}

func groupActorFromClaims(claims verify.Claims) (groupMutationActor, error) {
	if claims.UserID != "" && claims.TokenType == "" && claims.RemoteApplicationID == "" && claims.DelegatedSubject == "" {
		return groupMutationActor{userID: claims.UserID}, nil
	}
	if claims.TokenType != verify.RemoteApplicationTokenType || !strings.EqualFold(claims.TokenTyp, verify.RemoteApplicationAccessTokenType) || claims.RemoteApplicationID == "" || claims.UserID != "" || claims.DelegatedSubject != "" {
		return groupMutationActor{}, ErrInsufficientRoleAuthority
	}
	return groupMutationActor{remote: &claims}, nil
}

func (s *engine) groupMutationSubject(ctx context.Context, st *PermissionGroupStore, persona authkit.Persona, gid string, actor groupMutationActor) (authkit.Subject, error) {
	if actor.remote == nil {
		actor.userID = strings.TrimSpace(actor.userID)
		if actor.userID == "" {
			return authkit.Subject{}, ErrInsufficientRoleAuthority
		}
		present, err := authorizationActorPresent(ctx, st.q, actor.userID)
		if err != nil {
			return authkit.Subject{}, err
		}
		if !present {
			return authkit.Subject{}, ErrInsufficientRoleAuthority
		}
		return authkit.UserSubject(actor.userID), nil
	}
	c := actor.remote
	if !c.PermissionGroupAllows(verify.PermissionScope{GroupID: gid, AuthorityIssuer: s.cfg.Token.Issuer, Persona: persona}) {
		return authkit.Subject{}, ErrInsufficientRoleAuthority
	}
	var enabled bool
	err := st.q.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM remote_applications a JOIN permission_groups g ON g.id=a.permission_group_id WHERE a.id=$1::uuid AND a.issuer=$2 AND a.enabled AND g.id=$3::uuid AND g.persona=$4)`, c.RemoteApplicationID, c.Issuer, gid, persona).Scan(&enabled)
	if err != nil {
		return authkit.Subject{}, err
	}
	if !enabled {
		return authkit.Subject{}, ErrInsufficientRoleAuthority
	}
	return authkit.RemoteAppSubject(c.RemoteApplicationID), nil
}
