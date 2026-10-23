package remote

import (
	"context"
	"net/http"

	"github.com/open-rails/authkit/auth"
	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/internal/errmodel"
	"github.com/open-rails/authkit/internal/ops"
)

// Native transaction and other operation options cannot be silently ignored by
// an HTTP operation. Additional transportable options need explicit mappings.
func noNativeOptions(options []ops.Option) error {
	if len(options) > 0 {
		return errmodel.E(errmodel.CodeInvalidRequest, errmodel.WithParam("options"))
	}
	return nil
}
func (c *Client) CreateGroupOAuthClient(ctx context.Context, who auth.Identity, ref iam.GroupRef, in iam.NewOAuthClient, options ...ops.Option) (iam.OAuthClientCreated, error) {
	var out iam.OAuthClientCreated
	if err := noNativeOptions(options); err != nil {
		return out, err
	}
	path, err := groupPath(ref)
	if err != nil {
		return out, err
	}
	err = c.request(ctx, http.MethodPost, path+"/oauth-clients", nil, &who, in, &out)
	return out, err
}
func (c *Client) UpdateGroupOAuthClient(ctx context.Context, who auth.Identity, ref iam.GroupRef, id string, in iam.OAuthClientUpdate, options ...ops.Option) (iam.OAuthClient, error) {
	var out iam.OAuthClient
	if err := noNativeOptions(options); err != nil {
		return out, err
	}
	path, err := oauthClientPath(ref, id)
	if err != nil {
		return out, err
	}
	err = c.request(ctx, http.MethodPatch, path, nil, &who, in, &out)
	return out, err
}
func (c *Client) RotateGroupOAuthClientSecret(ctx context.Context, who auth.Identity, ref iam.GroupRef, id string, options ...ops.Option) (string, error) {
	if err := noNativeOptions(options); err != nil {
		return "", err
	}
	path, err := oauthClientPath(ref, id)
	if err != nil {
		return "", err
	}
	var out struct {
		Secret string `json:"client_secret"`
	}
	err = c.request(ctx, http.MethodPost, path+"/secret", nil, &who, nil, &out)
	return out.Secret, err
}
func (c *Client) DeleteGroupOAuthClient(ctx context.Context, who auth.Identity, ref iam.GroupRef, id string, options ...ops.Option) error {
	if err := noNativeOptions(options); err != nil {
		return err
	}
	path, err := oauthClientPath(ref, id)
	if err != nil {
		return err
	}
	return c.request(ctx, http.MethodDelete, path, nil, &who, nil, nil)
}
