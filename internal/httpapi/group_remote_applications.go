package httpapi

// A group's remote applications: /groups/{group_id}/remote-applications, a
// backend's signing keys for its RFC 7523 assertions (customer tokens),
// under <persona>:credentials:read and :manage, changes with a recent sign-in.

import (
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/open-rails/authkit/auth"
	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/internal/errmodel"
)

// RemoteApplication is one of the group's remote applications.
type RemoteApplication struct {
	ID      string                    `json:"id"`
	GroupID string                    `json:"group_id"`
	Issuer  string                    `json:"issuer"`
	Mode    iam.RemoteApplicationMode `json:"mode"`
	// JWKSURI is where its keys are read and rotated (jwks mode).
	JWKSURI *string `json:"jwks_uri"`
	// PublicKeys are its static keys (static mode).
	PublicKeys []RemoteApplicationPublicKey `json:"public_keys"`
	Enabled    bool                         `json:"enabled"`
	// TrustRoot user: the group's credential managers change it; manual: only
	// the operator.
	TrustRoot iam.ApplicationTrustRoot `json:"trust_root"`
	// Role is its role in the group, the ceiling of its tokens.
	Role      *string   `json:"role"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// RemoteApplicationPublicKey is one static key: its kid, and its PEM when it
// was registered as one (null for a JWK).
type RemoteApplicationPublicKey struct {
	KID          string  `json:"kid"`
	PublicKeyPEM *string `json:"public_key_pem"`
}

// RemoteApplicationCreateRequest registers an issuer with one trust source:
// a JWKS URL or static keys. It is enabled unless enabled is false.
type RemoteApplicationCreateRequest struct {
	Issuer     string                     `json:"issuer"`
	JWKSURI    string                     `json:"jwks_uri"`
	PublicKeys []iam.RemoteApplicationKey `json:"public_keys"`
	Enabled    *bool                      `json:"enabled"`
}

// RemoteApplicationUpdateRequest changes what it names: a JWKS URL or static
// keys replace the trust source; enabled turns its tokens on or off.
type RemoteApplicationUpdateRequest struct {
	JWKSURI    *string                    `json:"jwks_uri"`
	PublicKeys []iam.RemoteApplicationKey `json:"public_keys"`
	Enabled    *bool                      `json:"enabled"`
}

func remoteApplicationWire(a iam.RemoteApplication) RemoteApplication {
	out := RemoteApplication{ID: a.ID, GroupID: a.GroupID, Issuer: a.Issuer, Mode: a.Mode, PublicKeys: []RemoteApplicationPublicKey{},
		Enabled: a.Enabled, TrustRoot: a.TrustRoot, CreatedAt: a.CreatedAt, UpdatedAt: a.UpdatedAt}
	if a.JWKSURI != "" {
		out.JWKSURI = &a.JWKSURI
	}
	for _, k := range a.PublicKeys {
		key := RemoteApplicationPublicKey{KID: k.KID}
		if key.KID == "" && k.JWK != nil {
			key.KID = k.JWK.Kid
		}
		if k.PublicKeyPEM != "" {
			key.PublicKeyPEM = &k.PublicKeyPEM
		}
		out.PublicKeys = append(out.PublicKeys, key)
	}
	if !a.Role.IsZero() {
		role := a.Role.String()
		out.Role = &role
	}
	return out
}

func (s *Service) groupRemoteAppsList(w http.ResponseWriter, r *http.Request, g iam.Group) {
	p, ok := readPage(w, r)
	if !ok {
		return
	}
	page, err := s.svc.ListRemoteApplications(r.Context(), iam.GroupByID(g.ID), p)
	if err != nil {
		writeError(w, err)
		return
	}
	out := iam.ListPage[RemoteApplication]{Items: make([]RemoteApplication, 0, len(page.Items)), Next: page.Next, Total: page.Total}
	for _, a := range page.Items {
		out.Items = append(out.Items, remoteApplicationWire(a))
	}
	list(w, out)
}

// groupRemoteAppCreate registers a new issuer; one registered anywhere
// already is a conflict, so a create never re-keys an application.
func (s *Service) groupRemoteAppCreate(w http.ResponseWriter, r *http.Request, g iam.Group, who auth.Identity) {
	var body RemoteApplicationCreateRequest
	if err := decodeJSON(r, &body); err != nil {
		fail(w, errmodel.CodeInvalidRequest)
		return
	}
	issuer := strings.TrimSpace(body.Issuer)
	if issuer == "" {
		fail(w, errmodel.CodeInvalidRequest, errmodel.WithParam("issuer"))
		return
	}
	_, err := s.svc.RemoteApplication(r.Context(), iam.AppByIssuer(issuer))
	switch {
	case err == nil:
		writeError(w, iam.ErrRemoteApplicationIssuerConflict)
		return
	case !errors.Is(err, iam.ErrRemoteApplicationNotFound):
		writeError(w, err)
		return
	}
	app, err := s.svc.UpsertRemoteApplication(r.Context(), who, iam.GroupByID(g.ID), iam.RemoteApplication{
		Issuer: issuer, JWKSURI: body.JWKSURI, PublicKeys: body.PublicKeys, Enabled: body.Enabled == nil || *body.Enabled,
	})
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, remoteApplicationWire(app))
}

// groupRemoteAppUpdate changes the group's application {id}, keeping what
// the body does not name.
func (s *Service) groupRemoteAppUpdate(w http.ResponseWriter, r *http.Request, g iam.Group, who auth.Identity) {
	var body RemoteApplicationUpdateRequest
	if err := decodeJSON(r, &body); err != nil {
		fail(w, errmodel.CodeInvalidRequest)
		return
	}
	if body.JWKSURI != nil && body.PublicKeys != nil {
		fail(w, errmodel.CodeInvalidRequest, errmodel.WithParam("public_keys"))
		return
	}
	app, ok := s.groupRemoteApp(w, r, g)
	if !ok {
		return
	}
	next := iam.RemoteApplication{Issuer: app.Issuer, Mode: app.Mode, JWKSURI: app.JWKSURI, PublicKeys: app.PublicKeys,
		Enabled: app.Enabled, RoleMap: app.RoleMap}
	switch {
	case body.JWKSURI != nil:
		next.Mode, next.JWKSURI, next.PublicKeys = "", *body.JWKSURI, nil
	case body.PublicKeys != nil:
		next.Mode, next.JWKSURI, next.PublicKeys = "", "", body.PublicKeys
	}
	if body.Enabled != nil {
		next.Enabled = *body.Enabled
	}
	out, err := s.svc.UpsertRemoteApplication(r.Context(), who, iam.GroupByID(g.ID), next)
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, remoteApplicationWire(out))
}

func (s *Service) groupRemoteAppDelete(w http.ResponseWriter, r *http.Request, g iam.Group, who auth.Identity) {
	if err := s.svc.DeleteRemoteApplication(r.Context(), who, iam.GroupByID(g.ID), r.PathValue("id")); err != nil {
		writeError(w, err)
		return
	}
	noContent(w)
}

// groupRemoteApp is the application {id} the group controls; another
// group's, or none, is 404.
func (s *Service) groupRemoteApp(w http.ResponseWriter, r *http.Request, g iam.Group) (iam.RemoteApplication, bool) {
	app, err := s.svc.RemoteApplication(r.Context(), iam.AppByID(r.PathValue("id")))
	if err == nil && app.GroupID != g.ID {
		err = iam.ErrRemoteApplicationNotFound
	}
	if err != nil {
		writeError(w, err)
		return iam.RemoteApplication{}, false
	}
	return app, true
}

// NativeRemoteApplication is the lossless operation result, separate from the browser summary.
type NativeRemoteApplication iam.RemoteApplication

// groupRemoteAppsNativeList retains the native public-key and grant fields;
// the browser list above keeps its established presentation projection.
func (s *Service) groupRemoteAppsNativeList(w http.ResponseWriter, r *http.Request, g iam.Group) {
	p, ok := readPage(w, r)
	if !ok {
		return
	}
	page, err := s.svc.ListRemoteApplications(r.Context(), iam.GroupByID(g.ID), p)
	if err != nil {
		writeError(w, err)
		return
	}
	out := iam.ListPage[NativeRemoteApplication]{Items: make([]NativeRemoteApplication, 0, len(page.Items)), Next: page.Next, Total: page.Total}
	for _, app := range page.Items {
		out.Items = append(out.Items, NativeRemoteApplication(app))
	}
	list(w, out)
}
