package remote

import (
	"context"
	"net/http"
	"net/url"
	"time"

	"github.com/google/uuid"
	"github.com/open-rails/authkit/auth"
	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/internal/ops"
)

func (c *Client) CreateGroupRole(ctx context.Context, who auth.Identity, ref iam.GroupRef, in iam.NewGroupRole, options ...ops.Option) (iam.GroupRole, error) {
	var out iam.GroupRole
	if err := noNativeOptions(options); err != nil {
		return out, err
	}
	path, err := groupPath(ref)
	if err != nil {
		return out, err
	}
	body := struct {
		Name        string     `json:"name"`
		Permissions []iam.Perm `json:"permissions"`
	}{in.Name, in.Permissions}
	err = c.request(ctx, http.MethodPost, path+"/roles", nil, &who, body, &out)
	return out, err
}
func (c *Client) UpdateGroupRole(ctx context.Context, who auth.Identity, ref iam.GroupRef, role iam.Role, in iam.GroupRoleUpdate, options ...ops.Option) (iam.GroupRole, error) {
	var out iam.GroupRole
	if err := noNativeOptions(options); err != nil {
		return out, err
	}
	path, err := groupPath(ref)
	if err != nil {
		return out, err
	}
	body := struct {
		Permissions []iam.Perm `json:"permissions"`
	}{in.Permissions}
	err = c.request(ctx, http.MethodPatch, path+"/roles/"+url.PathEscape(role.String()), nil, &who, body, &out)
	return out, err
}
func (c *Client) DeleteGroupRole(ctx context.Context, who auth.Identity, ref iam.GroupRef, role iam.Role, options ...ops.Option) error {
	if err := noNativeOptions(options); err != nil {
		return err
	}
	path, err := groupPath(ref)
	if err != nil {
		return err
	}
	return c.request(ctx, http.MethodDelete, path+"/roles/"+url.PathEscape(role.String()), nil, &who, nil, nil)
}
func (c *Client) CreateAPIKey(ctx context.Context, who auth.Identity, ref iam.GroupRef, in iam.NewAPIKey, options ...ops.Option) (iam.APIKeyCreated, error) {
	var out iam.APIKeyCreated
	if err := noNativeOptions(options); err != nil {
		return out, err
	}
	path, err := groupPath(ref)
	if err != nil {
		return out, err
	}
	body := struct {
		Name          string     `json:"name"`
		Role          string     `json:"role"`
		ExpiresAt     *time.Time `json:"expires_at"`
		ProvisionsFor string     `json:"provisions_for,omitempty"`
	}{in.Name, in.Role.String(), in.ExpiresAt, in.ProvisionsFor}
	err = c.request(ctx, http.MethodPost, path+"/api-keys", nil, &who, body, &out)
	return out, err
}
func (c *Client) RevokeAPIKey(ctx context.Context, who auth.Identity, ref iam.GroupRef, id string, options ...ops.Option) error {
	if err := noNativeOptions(options); err != nil {
		return err
	}
	path, err := groupPath(ref)
	if err != nil {
		return err
	}
	parsed, err := uuid.Parse(id)
	if err != nil {
		return iam.ErrAPIKeyNotFound
	}
	return c.request(ctx, http.MethodDelete, path+"/api-keys/"+parsed.String(), nil, &who, nil, nil)
}
func (c *Client) DeleteRemoteApplication(ctx context.Context, who auth.Identity, ref iam.GroupRef, id string, options ...ops.Option) error {
	if err := noNativeOptions(options); err != nil {
		return err
	}
	path, err := groupPath(ref)
	if err != nil {
		return err
	}
	parsed, err := uuid.Parse(id)
	if err != nil {
		return iam.ErrRemoteApplicationNotFound
	}
	return c.request(ctx, http.MethodDelete, path+"/remote-applications/"+parsed.String(), nil, &who, nil, nil)
}
