package authflow

import (
	"time"

	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/internal/config"
)

// OAuthClient is a client of the authorization server: one Config declares
// (first-party, Group nil), or one a group registered at run time
// (third-party: its users consent to each scope, and its tokens act only in
// its group).
type OAuthClient struct {
	config.OAuthClientConfig
	Group *GroupClient
}

// GroupClient is what a group-registered client adds.
type GroupClient struct {
	GroupID              string
	AuthMethod           iam.OAuthClientAuthMethod
	JWKSURI              string
	Scopes               []string
	BackchannelLogoutURI string
	LogoURI              string
	ClientURI            string
	PolicyURI            string
	TOSURI               string
	UpdatedAt            time.Time
}

// ClientAssertionType is RFC 7523 §2.2's client_assertion_type.
const ClientAssertionType = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"

// ThirdParty reports whether the client is a group's, whose users consent.
func (c OAuthClient) ThirdParty() bool { return c.Group != nil }
