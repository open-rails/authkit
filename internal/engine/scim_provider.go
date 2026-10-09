package engine

// The read-only SCIM 2.0 service provider: GET /scim/v2/Users for
// client-credentials access tokens this deployment issued for its SCIM
// resource (config.SCIMResource) with scope scim:read.

import (
	"context"
	"errors"
	"slices"
	"strings"

	"github.com/jackc/pgx/v5"

	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/internal/authflow"
	"github.com/open-rails/authkit/internal/config"
	"github.com/open-rails/authkit/internal/db"
	"github.com/open-rails/authkit/internal/jose"
	"github.com/open-rails/authkit/internal/scim"
)

// AuthorizeSCIM accepts a client-credentials access token this deployment
// issued for its SCIM resource with scope scim:read, from a client still
// allowed it; jkt is the DPoP key the request proved, if any.
func (s *Engine) AuthorizeSCIM(_ context.Context, accessToken, jkt string) error {
	invalid := func(description string) error {
		return &authflow.OAuthError{Code: authflow.OAuthInvalidToken, Description: description, Status: 401}
	}
	claims, err := s.verifyOwnToken(accessToken, jose.ResourceAccessTokenType)
	if err != nil {
		return invalid("the access token is invalid")
	}
	if member, bound, err := jose.Confirmation(accessToken); err != nil || (member != "" && member != jose.JWKThumbprintMember) || bound != jkt {
		return invalid("the request does not prove the access token's DPoP key")
	}
	if exp, ok := jose.Time(claims, "exp"); !ok || !s.nowTime().Before(exp) {
		return invalid("the access token has expired")
	}
	resource := config.SCIMResource(s.cfg.Token.Issuer)
	if !slices.Contains(jose.Audiences(claims), resource) {
		return invalid("the access token is not for this SCIM service provider")
	}
	clientID := jose.String(claims, "client_id")
	client, ok := config.FindOAuthClient(s.cfg.AuthorizationServer, clientID)
	if !ok || jose.String(claims, "sub") != clientID || !config.OAuthClientAllows(client, config.GrantClientCredentials) || !slices.Contains(client.Resources, resource) {
		return invalid("the access token is not a client's own")
	}
	if !slices.Contains(strings.Fields(jose.String(claims, "scope")), config.SCIMReadScope) {
		return &authflow.OAuthError{Code: "insufficient_scope", Description: "the access token was not granted the " + config.SCIMReadScope + " scope", Status: 403}
	}
	return nil
}

// SCIMUser is the account id as a SCIM User; iam.ErrUserNotFound for none.
func (s *Engine) SCIMUser(ctx context.Context, id string) (scim.User, error) {
	if err := s.requirePG(); err != nil {
		return scim.User{}, err
	}
	id, ok := canonicalUUID(id)
	if !ok {
		return scim.User{}, iam.ErrUserNotFound
	}
	u, err := s.q.UserByID(ctx, id)
	if errors.Is(err, pgx.ErrNoRows) {
		return scim.User{}, iam.ErrUserNotFound
	}
	if err != nil {
		return scim.User{}, err
	}
	return s.servedSCIMUser(u), nil
}

// SCIMUsers answers a query: the accounts filter matches (scim.ParseFilter),
// or every account, in id order, from the 1-based startIndex.
func (s *Engine) SCIMUsers(ctx context.Context, filter string, startIndex, count int) (scim.ListResponse[scim.User], error) {
	out := scim.ListResponse[scim.User]{Schemas: []string{scim.SchemaListResponse}, StartIndex: max(startIndex, 1), Resources: []scim.User{}}
	if err := s.requirePG(); err != nil {
		return out, err
	}
	count = min(max(count, 0), scim.MaxResults)
	var rows []db.User
	if strings.TrimSpace(filter) == "" {
		total, err := s.q.SCIMUsersCount(ctx)
		if err != nil {
			return out, err
		}
		out.TotalResults = int(total)
		if count > 0 {
			if rows, err = s.q.SCIMUsersPage(ctx, db.SCIMUsersPageParams{PageSize: int64(count), Skip: int64(out.StartIndex - 1)}); err != nil {
				return out, err
			}
		}
	} else {
		f, err := scim.ParseFilter(filter)
		if err != nil {
			return out, err
		}
		ids := []string{}
		for _, id := range f.IDs {
			if id, ok := canonicalUUID(id); ok {
				ids = append(ids, id)
			}
		}
		matched, err := s.q.SCIMUsersMatching(ctx, db.SCIMUsersMatchingParams{Ids: ids, Usernames: nonNil(f.UserNames), Emails: nonNil(f.Emails)})
		if err != nil {
			return out, err
		}
		out.TotalResults = len(matched)
		from := min(out.StartIndex-1, len(matched))
		rows = matched[from:min(from+count, len(matched))]
	}
	for _, u := range rows {
		out.Resources = append(out.Resources, s.servedSCIMUser(u))
	}
	out.ItemsPerPage = len(out.Resources)
	return out, nil
}

// servedSCIMUser is u as this deployment serves it: id is the account's.
func (s *Engine) servedSCIMUser(u db.User) scim.User {
	out := scimUser(u, s.nowTime())
	out.ID, out.ExternalID = u.ID, ""
	created, modified := u.CreatedAt, u.ProfileUpdatedAt
	out.Meta = &scim.Meta{ResourceType: "User", Created: &created, LastModified: &modified}
	return out
}
