package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/internal/authflow"
	"github.com/open-rails/authkit/internal/config"
	"github.com/open-rails/authkit/internal/dpop"
	"github.com/open-rails/authkit/internal/jose"
	"github.com/open-rails/authkit/internal/scim"
)

// scimBackend is the read-only SCIM service provider (#441).
type scimBackend interface {
	AuthorizeSCIM(ctx context.Context, accessToken, jkt string) error
	SCIMUser(ctx context.Context, id string) (scim.User, error)
	SCIMUsers(ctx context.Context, filter string, startIndex, count int) (scim.ListResponse[scim.User], error)
}

// SCIMUsersQuery is GET /scim/v2/Users' query (RFC 7644 §3.4.2).
type SCIMUsersQuery struct {
	Filter     string `query:"filter"`
	StartIndex *int   `query:"startIndex"`
	Count      *int   `query:"count"`
}

// scimPath is where the service provider's endpoints are, beneath the
// issuer's path.
const scimPath = "/scim/v2"

func writeSCIM(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", scim.MediaType)
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func scimFail(w http.ResponseWriter, status int, scimType, detail string) {
	writeSCIM(w, status, scim.NewError(status, scimType, detail))
}

// scimRead serves a read for a client-credentials token with scope
// scim:read; anything else answers 401 or 403 with a SCIM error and the
// token's challenge.
func scimRead(f func(*Service, http.ResponseWriter, *http.Request)) func(*Service) http.Handler {
	return handle(func(s *Service, w http.ResponseWriter, r *http.Request) {
		token, isDPoP := jose.RequestToken(r)
		scheme := "Bearer"
		if isDPoP {
			scheme = "DPoP"
		}
		refuse := func(code, description string, status int) {
			w.Header().Set("WWW-Authenticate", scheme+` error="`+code+`"`)
			scimFail(w, status, "", description)
		}
		if token == "" {
			refuse(authflow.OAuthInvalidToken, "an access token is required", http.StatusUnauthorized)
			return
		}
		jkt := ""
		if isDPoP {
			var err error
			jkt, err = dpop.Verify(r, dpop.Check{URL: s.oauthURL(strings.TrimPrefix(r.URL.Path, s.http.BasePath)), AccessToken: token, Replay: s.replays.Claim})
			switch {
			case errors.Is(err, dpop.ErrReplayUnavailable):
				scimFail(w, http.StatusServiceUnavailable, "", "the DPoP proof cannot be checked now")
				return
			case err != nil:
				refuse(authflow.OAuthInvalidDPoPProof, "the DPoP proof is invalid or already used", http.StatusUnauthorized)
				return
			}
		}
		if err := s.svc.AuthorizeSCIM(r.Context(), token, jkt); err != nil {
			var oe *authflow.OAuthError
			if errors.As(err, &oe) {
				refuse(oe.Code, oe.Description, oe.Status)
				return
			}
			s.scimInternal(w, r, err)
			return
		}
		f(s, w, r)
	})
}

func (s *Service) scimInternal(w http.ResponseWriter, r *http.Request, err error) {
	s.logInternalError(r, "scim", "read", "internal_error", err)
	scimFail(w, http.StatusInternalServerError, "", "internal error")
}

// scimLocation is the absolute URL of a resource path beneath the service
// provider.
func (s *Service) scimLocation(path string) string { return s.oauthURL(scimPath + path) }

func (s *Service) handleSCIMServiceProviderConfig(w http.ResponseWriter, _ *http.Request) {
	writeSCIM(w, http.StatusOK, scim.ServiceProviderConfig{
		Schemas:          []string{scim.SchemaServiceProviderConfig},
		DocumentationURI: "https://github.com/open-rails/authkit/blob/master/docs/scim.md",
		Filter:           scim.FilterSupport{Supported: true, MaxResults: scim.MaxResults},
		AuthenticationSchemes: []scim.AuthScheme{{
			Type: "oauthbearertoken", Name: "OAuth Bearer Token", Primary: true,
			Description: "A client-credentials access token from this issuer for " + config.SCIMResource(s.cfg.Token.Issuer) + " with scope " + config.SCIMReadScope,
			SpecURI:     "https://www.rfc-editor.org/info/rfc6750",
		}},
		Meta: &scim.Meta{ResourceType: "ServiceProviderConfig", Location: s.scimLocation("/ServiceProviderConfig")},
	})
}

func (s *Service) userResourceType() scim.ResourceType {
	return scim.ResourceType{
		Schemas: []string{scim.SchemaResourceType}, ID: "User", Name: "User", Endpoint: "/Users",
		Description: "User Account", Schema: scim.SchemaUser,
		Meta: &scim.Meta{ResourceType: "ResourceType", Location: s.scimLocation("/ResourceTypes/User")},
	}
}

func (s *Service) handleSCIMResourceTypes(w http.ResponseWriter, _ *http.Request) {
	writeSCIM(w, http.StatusOK, scim.ListResponse[scim.ResourceType]{
		Schemas: []string{scim.SchemaListResponse}, TotalResults: 1, StartIndex: 1, ItemsPerPage: 1,
		Resources: []scim.ResourceType{s.userResourceType()},
	})
}

func (s *Service) handleSCIMResourceType(w http.ResponseWriter, r *http.Request) {
	if r.PathValue("id") != "User" {
		scimFail(w, http.StatusNotFound, "", "no such resource type")
		return
	}
	writeSCIM(w, http.StatusOK, s.userResourceType())
}

func (s *Service) userSchema() scim.SchemaDoc {
	doc := scim.UserSchema()
	doc.Meta = &scim.Meta{ResourceType: "Schema", Location: s.scimLocation("/Schemas/" + scim.SchemaUser)}
	return doc
}

func (s *Service) handleSCIMSchemas(w http.ResponseWriter, _ *http.Request) {
	writeSCIM(w, http.StatusOK, scim.ListResponse[scim.SchemaDoc]{
		Schemas: []string{scim.SchemaListResponse}, TotalResults: 1, StartIndex: 1, ItemsPerPage: 1,
		Resources: []scim.SchemaDoc{s.userSchema()},
	})
}

func (s *Service) handleSCIMSchema(w http.ResponseWriter, r *http.Request) {
	if r.PathValue("id") != scim.SchemaUser {
		scimFail(w, http.StatusNotFound, "", "no such schema")
		return
	}
	writeSCIM(w, http.StatusOK, s.userSchema())
}

func (s *Service) handleSCIMUser(w http.ResponseWriter, r *http.Request) {
	u, err := s.svc.SCIMUser(r.Context(), r.PathValue("id"))
	if errors.Is(err, iam.ErrUserNotFound) {
		scimFail(w, http.StatusNotFound, "", "no such user")
		return
	}
	if err != nil {
		s.scimInternal(w, r, err)
		return
	}
	u.Meta.Location = s.scimLocation("/Users/" + url.PathEscape(u.ID))
	writeSCIM(w, http.StatusOK, u)
}

func (s *Service) handleSCIMUsers(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	number := func(name string, fallback int) (int, bool) {
		raw := q.Get(name)
		if raw == "" {
			return fallback, true
		}
		n, err := strconv.Atoi(raw)
		if err != nil {
			scimFail(w, http.StatusBadRequest, "invalidValue", name+" must be an integer")
			return 0, false
		}
		return n, true
	}
	start, ok := number("startIndex", 1)
	if !ok {
		return
	}
	count, ok := number("count", scim.MaxResults)
	if !ok {
		return
	}
	page, err := s.svc.SCIMUsers(r.Context(), q.Get("filter"), start, count)
	if errors.Is(err, scim.ErrInvalidFilter) {
		scimFail(w, http.StatusBadRequest, "invalidFilter", err.Error())
		return
	}
	if err != nil {
		s.scimInternal(w, r, err)
		return
	}
	for i := range page.Resources {
		page.Resources[i].Meta.Location = s.scimLocation("/Users/" + url.PathEscape(page.Resources[i].ID))
	}
	writeSCIM(w, http.StatusOK, page)
}

// handleSCIMReadOnly answers a write: this service provider only reads
// (RFC 7644 §3.12).
func (s *Service) handleSCIMReadOnly(w http.ResponseWriter, _ *http.Request) {
	scimFail(w, http.StatusNotImplemented, "", "this SCIM service provider is read-only")
}
