package remote

import (
	"context"
	"net/url"
	"strconv"

	"github.com/google/uuid"
	"github.com/open-rails/authkit/iam"
)

func pageQuery(p iam.PageRequest) url.Values {
	q := url.Values{"limit": []string{strconv.Itoa(p.PageLimit())}}
	if p.Cursor != "" {
		q.Set("cursor", p.Cursor)
	}
	return q
}

func groupPath(ref iam.GroupRef) (string, error) {
	if ref.IsRoot() {
		return "/groups/root", nil
	}
	id, err := uuid.Parse(ref.ID())
	if err != nil {
		return "", iam.ErrGroupNotFound
	}
	return "/groups/" + id.String(), nil
}
func userPath(id string) (string, error) {
	parsed, err := uuid.Parse(id)
	if err != nil {
		return "", iam.ErrUserNotFound
	}
	return "/admin/users/" + parsed.String(), nil
}

func oauthClientPath(ref iam.GroupRef, id string) (string, error) {
	if id == "" || id == "." || id == ".." {
		return "", iam.ErrOAuthClientNotFound
	}
	path, err := groupPath(ref)
	if err != nil {
		return "", err
	}
	return path + "/oauth-clients/" + url.PathEscape(id), nil
}

func (c *Client) ListEvents(ctx context.Context, q iam.EventQuery) (iam.EventPage, error) {
	v := url.Values{}
	if q.After != "" {
		v.Set("after", q.After)
	}
	if q.Limit != 0 {
		v.Set("limit", strconv.Itoa(q.Limit))
	}
	if q.Authority {
		v.Set("authority", "true")
	}
	for _, kind := range q.Kinds {
		v.Add("kind", string(kind))
	}
	for _, kind := range q.Types {
		v.Add("type", kind)
	}
	var out iam.EventPage
	err := c.get(ctx, "/events", v, &out)
	return out, err
}

func (c *Client) ListUsers(ctx context.Context, q iam.UserQuery) (iam.ListPage[iam.UserEntry], error) {
	v := pageQuery(q.Page)
	v.Set("search", q.Search)
	v.Set("status", string(q.Status))
	v.Set("sort", string(q.Sort))
	v.Set("entitlement", q.Entitlement)
	v.Set("root_role", q.RootRole.String())
	v.Set("tenant_role", q.TenantRole.String())
	v.Set("total", strconv.FormatBool(q.Total))
	v.Set("with_entitlements", strconv.FormatBool(q.WithEntitlements))
	v.Set("order", "asc")
	if q.Desc {
		v.Set("order", "desc")
	}
	var out iam.ListPage[iam.UserEntry]
	err := c.get(ctx, "/admin/users", v, &out)
	return out, err
}

func (c *Client) Sessions(ctx context.Context, userID string) ([]iam.Session, error) {
	path, err := userPath(userID)
	if err != nil {
		return nil, err
	}
	var out iam.ListPage[iam.Session]
	err = c.get(ctx, path+"/sessions", nil, &out)
	return out.Items, err
}
func (c *Client) ListSessionEvents(ctx context.Context, userID string, q iam.SessionEventQuery) (iam.ListPage[iam.SessionEvent], error) {
	var out iam.ListPage[iam.SessionEvent]
	path, err := userPath(userID)
	if err != nil {
		return out, err
	}
	v := pageQuery(q.Page)
	for _, kind := range q.Kinds {
		v.Add("kind", string(kind))
	}
	err = c.get(ctx, path+"/session-events", v, &out)
	return out, err
}
func (c *Client) GroupOAuthClients(ctx context.Context, ref iam.GroupRef) ([]iam.OAuthClient, error) {
	path, err := groupPath(ref)
	if err != nil {
		return nil, err
	}
	var out iam.ListPage[iam.OAuthClient]
	err = c.get(ctx, path+"/oauth-clients", nil, &out)
	return out.Items, err
}
func (c *Client) GroupOAuthClient(ctx context.Context, ref iam.GroupRef, id string) (iam.OAuthClient, error) {
	var out iam.OAuthClient
	path, err := oauthClientPath(ref, id)
	if err != nil {
		return out, err
	}
	err = c.get(ctx, path, nil, &out)
	return out, err
}
func (c *Client) ListGroupRoles(ctx context.Context, ref iam.GroupRef) ([]iam.GroupRole, error) {
	path, err := groupPath(ref)
	if err != nil {
		return nil, err
	}
	var out iam.ListPage[iam.GroupRole]
	err = c.get(ctx, path+"/roles", nil, &out)
	return out.Items, err
}
func (c *Client) GroupRole(ctx context.Context, ref iam.GroupRef, role iam.Role) (iam.GroupRole, error) {
	var out iam.GroupRole
	path, err := groupPath(ref)
	if err != nil {
		return out, err
	}
	err = c.get(ctx, path+"/roles/"+url.PathEscape(role.String()), nil, &out)
	return out, err
}
func (c *Client) ListAPIKeys(ctx context.Context, ref iam.GroupRef, p iam.PageRequest) (iam.ListPage[iam.APIKey], error) {
	var out iam.ListPage[iam.APIKey]
	path, err := groupPath(ref)
	if err != nil {
		return out, err
	}
	err = c.get(ctx, path+"/api-keys", pageQuery(p), &out)
	return out, err
}
func (c *Client) ListInvitations(ctx context.Context, ref iam.GroupRef, p iam.PageRequest) (iam.ListPage[iam.Invitation], error) {
	var out iam.ListPage[iam.Invitation]
	path, err := groupPath(ref)
	if err != nil {
		return out, err
	}
	err = c.get(ctx, path+"/invitations", pageQuery(p), &out)
	return out, err
}
func (c *Client) ListRemoteApplications(ctx context.Context, ref iam.GroupRef, p iam.PageRequest) (iam.ListPage[iam.RemoteApplication], error) {
	var out iam.ListPage[iam.RemoteApplication]
	path, err := groupPath(ref)
	if err != nil {
		return out, err
	}
	err = c.get(ctx, path+"/remote-applications", pageQuery(p), &out)
	return out, err
}
func (c *Client) ProvisioningTargets(ctx context.Context) ([]iam.ProvisioningTarget, error) {
	var out iam.ListPage[iam.ProvisioningTarget]
	err := c.get(ctx, "/admin/provisioning/targets", nil, &out)
	return out.Items, err
}
func (c *Client) GenerateUsername(ctx context.Context) (string, error) {
	var out struct {
		Username string `json:"username"`
	}
	err := c.get(ctx, "/usernames/generate", nil, &out)
	return out.Username, err
}
