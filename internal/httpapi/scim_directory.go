package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/open-rails/authkit/internal/ident"
	"github.com/open-rails/authkit/internal/scim"
	"github.com/open-rails/authkit/verify"
	"github.com/open-rails/helpers/auth"
)

// scimDirectoryBackend is a group's directory of its remote applications'
// users, as a SCIM 2.0 service provider (RFC 7643, RFC 7644). Failures a
// client caused are *scim.StatusError.
type scimDirectoryBackend interface {
	SCIMTenant(ctx context.Context, who auth.Identity, boundGroup string) (scim.Tenant, error)
	DirectoryUser(ctx context.Context, t scim.Tenant, id string) (scim.User, error)
	DirectoryUsers(ctx context.Context, t scim.Tenant, filter string, startIndex, count int) (scim.ListResponse[scim.User], error)
	CreateDirectoryUser(ctx context.Context, t scim.Tenant, u scim.User) (scim.User, error)
	ReplaceDirectoryUser(ctx context.Context, t scim.Tenant, id string, u scim.User) (scim.User, error)
	PatchDirectoryUser(ctx context.Context, t scim.Tenant, id string, req scim.PatchRequest) (scim.User, error)
	DeleteDirectoryUser(ctx context.Context, t scim.Tenant, id string) error
}

// scimDirectoryPath is where a directory's service provider is, beneath the
// issuer's path.
const scimDirectoryPath = "/directory/scim/v2"

// Directory limits the service provider advertises.
const (
	scimMaxUserBytes   = 64 << 10
	scimBulkOperations = 1000
	scimBulkPayload    = 1 << 20
)

// boundScope is a Verified bound to one scope: a trusted issuer's token, its
// application's group (helpers/auth Bound).
type boundScope interface{ BoundScope() auth.Scope }

// scimDirectory serves a request to a group's directory. The credential is
// authenticated as Client.Authenticator authenticates it, and names the
// tenant (RFC 7644 §6.1): an API key bound to a remote application, or the
// application's own token. It must hold <persona>:directory:manage there,
// or :read for a read. A refusal is a SCIM error (RFC 7644 §3.12) with
// RFC 6750's challenge.
func scimDirectory(manage bool, f func(*Service, http.ResponseWriter, *http.Request, scim.Tenant)) func(*Service) http.Handler {
	return handle(func(s *Service, w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		v, err := verify.AuthenticateSession(ctx, s.svc, r)
		if err != nil {
			s.scimRefuse(w, r, err)
			return
		}
		bound := ""
		if b, ok := v.(boundScope); ok && b.BoundScope().Authority == s.cfg.Token.Issuer {
			bound = b.BoundScope().ID
		}
		t, err := s.svc.SCIMTenant(ctx, v.Identity(), bound)
		if errors.Is(err, scim.ErrNoTenant) {
			scimFail(w, http.StatusForbidden, "", "the credential provisions no remote application's users: use an API key bound to one, or the application's own token")
			return
		}
		if err != nil {
			s.scimDirectoryInternal(w, r, err)
			return
		}
		perm := ident.DirectoryRead(ident.Persona(t.Persona))
		if manage {
			perm = ident.DirectoryManage(ident.Persona(t.Persona))
		}
		checker, ok := v.(auth.PermissionChecker)
		allowed := false
		if ok {
			allowed, err = checker.Can(ctx, auth.Scope{Authority: s.cfg.Token.Issuer, ID: t.GroupID}, perm.String())
		}
		if err != nil {
			s.scimRefuse(w, r, err)
			return
		}
		if !allowed {
			w.Header().Set("WWW-Authenticate", `Bearer error="insufficient_scope"`)
			scimFail(w, http.StatusForbidden, "", "the credential lacks "+perm.String())
			return
		}
		f(s, w, r, t)
	})
}

// scimRefuse answers a refused credential: 401 with its challenge (RFC 6750
// §3, or the credential's own), 403, or 503.
func (s *Service) scimRefuse(w http.ResponseWriter, r *http.Request, err error) {
	var c *auth.Challenge
	if errors.As(err, &c) {
		for name, values := range c.Header {
			for _, v := range values {
				w.Header().Add(name, v)
			}
		}
	}
	switch {
	case errors.Is(err, auth.ErrUnavailable):
		scimFail(w, http.StatusServiceUnavailable, "", "the credential cannot be checked now")
	case errors.Is(err, auth.ErrForbidden):
		scimFail(w, http.StatusForbidden, "", "the credential is refused")
	default:
		if w.Header().Get("WWW-Authenticate") == "" {
			challenge := "Bearer"
			if r.Header.Get("Authorization") != "" {
				challenge += ` error="invalid_token"`
			}
			w.Header().Set("WWW-Authenticate", challenge)
		}
		scimFail(w, http.StatusUnauthorized, "", "a valid credential is required")
	}
}

func (s *Service) scimDirectoryInternal(w http.ResponseWriter, r *http.Request, err error) {
	s.logInternalError(r, "scim_directory", "serve", "internal_error", err)
	scimFail(w, http.StatusInternalServerError, "", "internal error")
}

// scimDirectoryResult writes a backend's answer: a client error as SCIM's
// error, anything else as 500.
func (s *Service) scimDirectoryResult(w http.ResponseWriter, r *http.Request, status int, u scim.User, err error) {
	var se *scim.StatusError
	switch {
	case errors.As(err, &se):
		scimFail(w, se.Status, se.ScimType, se.Detail)
	case errors.Is(err, scim.ErrInvalidFilter):
		scimFail(w, http.StatusBadRequest, "invalidFilter", err.Error())
	case err != nil:
		s.scimDirectoryInternal(w, r, err)
	default:
		location := s.directoryLocation("/Users/" + url.PathEscape(u.ID))
		u.Meta.Location = location
		if status == http.StatusCreated {
			w.Header().Set("Location", location)
		}
		writeSCIM(w, status, u)
	}
}

func (s *Service) directoryLocation(path string) string {
	return s.oauthURL(scimDirectoryPath + path)
}

// decodeSCIM reads a JSON body of at most limit bytes into v.
func decodeSCIM(w http.ResponseWriter, r *http.Request, limit int64, v any) bool {
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, limit))
	var tooLarge *http.MaxBytesError
	switch {
	case errors.As(err, &tooLarge):
		scimFail(w, http.StatusRequestEntityTooLarge, "", "the request body is larger than "+strconv.FormatInt(limit, 10)+" bytes")
		return false
	case err != nil:
		scimFail(w, http.StatusBadRequest, "invalidSyntax", "the request body could not be read")
		return false
	case json.Unmarshal(body, v) != nil:
		scimFail(w, http.StatusBadRequest, "invalidSyntax", "the request body is not the JSON this endpoint takes")
		return false
	}
	return true
}

func (s *Service) handleDirectoryServiceProviderConfig(w http.ResponseWriter, _ *http.Request) {
	writeSCIM(w, http.StatusOK, scim.ServiceProviderConfig{
		Schemas:          []string{scim.SchemaServiceProviderConfig},
		DocumentationURI: "https://github.com/open-rails/authkit/blob/master/docs/scim.md",
		Patch:            scim.Supported{Supported: true},
		Bulk:             scim.BulkSupport{Supported: true, MaxOperations: scimBulkOperations, MaxPayloadSize: scimBulkPayload},
		Filter:           scim.FilterSupport{Supported: true, MaxResults: scim.MaxResults},
		AuthenticationSchemes: []scim.AuthScheme{{
			Type: "oauthbearertoken", Name: "OAuth Bearer Token", Primary: true,
			Description: "An API key bound to a remote application, or the application's own access token for this deployment",
			SpecURI:     "https://www.rfc-editor.org/info/rfc6750",
		}},
		Meta: &scim.Meta{ResourceType: "ServiceProviderConfig", Location: s.directoryLocation("/ServiceProviderConfig")},
	})
}

func (s *Service) directoryResourceType() scim.ResourceType {
	return scim.ResourceType{
		Schemas: []string{scim.SchemaResourceType}, ID: "User", Name: "User", Endpoint: "/Users",
		Description: "User Account", Schema: scim.SchemaUser,
		Meta: &scim.Meta{ResourceType: "ResourceType", Location: s.directoryLocation("/ResourceTypes/User")},
	}
}

func (s *Service) handleDirectoryResourceTypes(w http.ResponseWriter, _ *http.Request) {
	writeSCIM(w, http.StatusOK, scim.ListResponse[scim.ResourceType]{
		Schemas: []string{scim.SchemaListResponse}, TotalResults: 1, StartIndex: 1, ItemsPerPage: 1,
		Resources: []scim.ResourceType{s.directoryResourceType()},
	})
}

func (s *Service) handleDirectoryResourceType(w http.ResponseWriter, r *http.Request) {
	if r.PathValue("id") != "User" {
		scimFail(w, http.StatusNotFound, "", "no such resource type")
		return
	}
	writeSCIM(w, http.StatusOK, s.directoryResourceType())
}

func (s *Service) directorySchema() scim.SchemaDoc {
	doc := scim.DirectoryUserSchema()
	doc.Meta = &scim.Meta{ResourceType: "Schema", Location: s.directoryLocation("/Schemas/" + scim.SchemaUser)}
	return doc
}

func (s *Service) handleDirectorySchemas(w http.ResponseWriter, _ *http.Request) {
	writeSCIM(w, http.StatusOK, scim.ListResponse[scim.SchemaDoc]{
		Schemas: []string{scim.SchemaListResponse}, TotalResults: 1, StartIndex: 1, ItemsPerPage: 1,
		Resources: []scim.SchemaDoc{s.directorySchema()},
	})
}

func (s *Service) handleDirectorySchema(w http.ResponseWriter, r *http.Request) {
	if r.PathValue("id") != scim.SchemaUser {
		scimFail(w, http.StatusNotFound, "", "no such schema")
		return
	}
	writeSCIM(w, http.StatusOK, s.directorySchema())
}

func (s *Service) handleDirectoryUsers(w http.ResponseWriter, r *http.Request, t scim.Tenant) {
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
	page, err := s.svc.DirectoryUsers(r.Context(), t, q.Get("filter"), start, count)
	if errors.Is(err, scim.ErrInvalidFilter) {
		scimFail(w, http.StatusBadRequest, "invalidFilter", err.Error())
		return
	}
	if err != nil {
		s.scimDirectoryInternal(w, r, err)
		return
	}
	for i := range page.Resources {
		page.Resources[i].Meta.Location = s.directoryLocation("/Users/" + url.PathEscape(page.Resources[i].ID))
	}
	writeSCIM(w, http.StatusOK, page)
}

func (s *Service) handleDirectoryUser(w http.ResponseWriter, r *http.Request, t scim.Tenant) {
	u, err := s.svc.DirectoryUser(r.Context(), t, r.PathValue("id"))
	s.scimDirectoryResult(w, r, http.StatusOK, u, err)
}

func (s *Service) handleDirectoryCreate(w http.ResponseWriter, r *http.Request, t scim.Tenant) {
	var in scim.User
	if !decodeSCIM(w, r, scimMaxUserBytes, &in) {
		return
	}
	u, err := s.svc.CreateDirectoryUser(r.Context(), t, in)
	s.scimDirectoryResult(w, r, http.StatusCreated, u, err)
}

func (s *Service) handleDirectoryReplace(w http.ResponseWriter, r *http.Request, t scim.Tenant) {
	var in scim.User
	if !decodeSCIM(w, r, scimMaxUserBytes, &in) {
		return
	}
	u, err := s.svc.ReplaceDirectoryUser(r.Context(), t, r.PathValue("id"), in)
	s.scimDirectoryResult(w, r, http.StatusOK, u, err)
}

func (s *Service) handleDirectoryPatch(w http.ResponseWriter, r *http.Request, t scim.Tenant) {
	var in scim.PatchRequest
	if !decodeSCIM(w, r, scimMaxUserBytes, &in) {
		return
	}
	u, err := s.svc.PatchDirectoryUser(r.Context(), t, r.PathValue("id"), in)
	s.scimDirectoryResult(w, r, http.StatusOK, u, err)
}

func (s *Service) handleDirectoryDelete(w http.ResponseWriter, r *http.Request, t scim.Tenant) {
	err := s.svc.DeleteDirectoryUser(r.Context(), t, r.PathValue("id"))
	var se *scim.StatusError
	switch {
	case errors.As(err, &se):
		scimFail(w, se.Status, se.ScimType, se.Detail)
	case err != nil:
		s.scimDirectoryInternal(w, r, err)
	default:
		w.WriteHeader(http.StatusNoContent)
	}
}

// directoryBulkRequest is a bulk request as received: each operation's data
// is decoded by its method.
type directoryBulkRequest struct {
	Schemas      []string `json:"schemas"`
	FailOnErrors *int     `json:"failOnErrors"`
	Operations   []struct {
		Method string          `json:"method"`
		BulkID string          `json:"bulkId"`
		Path   string          `json:"path"`
		Data   json.RawMessage `json:"data"`
	} `json:"Operations"`
}

// handleDirectoryBulk applies a bulk request's operations in order, each on
// its own (RFC 7644 §3.7), stopping once failOnErrors of them failed.
func (s *Service) handleDirectoryBulk(w http.ResponseWriter, r *http.Request, t scim.Tenant) {
	var in directoryBulkRequest
	if !decodeSCIM(w, r, scimBulkPayload, &in) {
		return
	}
	switch {
	case !containsFold(in.Schemas, scim.SchemaBulkRequest):
		scimFail(w, http.StatusBadRequest, "invalidSyntax", "schemas must name "+scim.SchemaBulkRequest)
		return
	case len(in.Operations) > scimBulkOperations:
		scimFail(w, http.StatusRequestEntityTooLarge, "", "a bulk request takes at most "+strconv.Itoa(scimBulkOperations)+" operations")
		return
	}
	out := scim.BulkResponse{Schemas: []string{scim.SchemaBulkResponse}, Operations: []scim.BulkResult{}}
	failed := 0
	for _, op := range in.Operations {
		if in.FailOnErrors != nil && *in.FailOnErrors > 0 && failed >= *in.FailOnErrors {
			break
		}
		res := s.directoryBulkOperation(r, t, strings.ToUpper(op.Method), op.Path, op.Data)
		res.BulkID = op.BulkID
		if res.Status >= 400 {
			failed++
		}
		out.Operations = append(out.Operations, res)
	}
	writeSCIM(w, http.StatusOK, out)
}

func (s *Service) directoryBulkOperation(r *http.Request, t scim.Tenant, method, path string, data json.RawMessage) scim.BulkResult {
	ctx := r.Context()
	res := scim.BulkResult{Method: method}
	fail := func(err error) scim.BulkResult {
		var se *scim.StatusError
		if !errors.As(err, &se) {
			s.logInternalError(r, "scim_directory", "bulk", "internal_error", err)
			se = scim.Fail(http.StatusInternalServerError, "", "internal error")
		}
		res.Status = scim.Status(se.Status)
		res.Response, _ = json.Marshal(scim.NewError(se.Status, se.ScimType, se.Detail))
		return res
	}
	done := func(status int, u scim.User, err error) scim.BulkResult {
		if err != nil {
			return fail(err)
		}
		res.Status, res.Location = scim.Status(status), s.directoryLocation("/Users/"+url.PathEscape(u.ID))
		return res
	}
	escaped, isUser := strings.CutPrefix(path, "/Users/")
	id, err := url.PathUnescape(escaped)
	isUser = isUser && err == nil && id != "" && !strings.Contains(escaped, "/")
	if isUser {
		res.Location = s.directoryLocation("/Users/" + url.PathEscape(id))
	}
	switch {
	case method == http.MethodPost && path == "/Users":
		var u scim.User
		if json.Unmarshal(data, &u) != nil {
			return fail(scim.Fail(http.StatusBadRequest, "invalidSyntax", "data is not a User"))
		}
		created, err := s.svc.CreateDirectoryUser(ctx, t, u)
		return done(http.StatusCreated, created, err)
	case method == http.MethodPut && isUser:
		var u scim.User
		if json.Unmarshal(data, &u) != nil {
			return fail(scim.Fail(http.StatusBadRequest, "invalidSyntax", "data is not a User"))
		}
		replaced, err := s.svc.ReplaceDirectoryUser(ctx, t, id, u)
		return done(http.StatusOK, replaced, err)
	case method == http.MethodPatch && isUser:
		var p scim.PatchRequest
		if json.Unmarshal(data, &p) != nil {
			return fail(scim.Fail(http.StatusBadRequest, "invalidSyntax", "data is not a PatchOp"))
		}
		patched, err := s.svc.PatchDirectoryUser(ctx, t, id, p)
		return done(http.StatusOK, patched, err)
	case method == http.MethodDelete && isUser:
		if err = s.svc.DeleteDirectoryUser(ctx, t, id); err != nil {
			return fail(err)
		}
		res.Status = http.StatusNoContent
		return res
	}
	return fail(scim.Fail(http.StatusBadRequest, "invalidPath", method+" "+path+" is not an operation on /Users"))
}

func containsFold(list []string, s string) bool {
	for _, v := range list {
		if strings.EqualFold(strings.TrimSpace(v), s) {
			return true
		}
	}
	return false
}
