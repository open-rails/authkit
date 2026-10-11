package harness

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"html/template"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/open-rails/authkit/keys"
	"github.com/open-rails/authkit/provider"
)

// The fake OpenID Provider the e2e server serves beneath IdPPath. Its page
// signs in as the subject typed there; a code carries that subject and what
// the request bound it to, so the IdP keeps no state.
const (
	IdPPath   = "/__test/idp"
	IdPClient = "e2e-idp"
	IdPSecret = "e2e-idp-secret-0123456789"
)

// IdPIssuer is the IdP's issuer: beneath the e2e server's origin.
func IdPIssuer(baseURL string) string { return baseURL + IdPPath }

type IdP struct {
	issuer string
	signer keys.Signer
}

func NewIdP(baseURL string) (*IdP, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}
	signer, err := keys.SignerFromKey("idp-1", key)
	if err != nil {
		return nil, err
	}
	return &IdP{issuer: IdPIssuer(baseURL), signer: signer}, nil
}

// Provider is the IdP as the "github" provider, so the sign-in pages keep
// their GitHub button while sign-in, linking and step-up really run.
func (p *IdP) Provider() provider.Provider {
	return provider.OIDC("github", p.issuer, IdPClient, IdPSecret,
		provider.WithDisplayName("GitHub"), provider.WithTrustedEmailVerification(true))
}

type grant struct {
	Subject       string `json:"sub"`
	Nonce         string `json:"nonce,omitempty"`
	RedirectURI   string `json:"redirect_uri"`
	CodeChallenge string `json:"code_challenge,omitempty"`
	AuthTime      int64  `json:"auth_time"`
}

var signInPage = template.Must(template.New("idp").Parse(`<!doctype html><meta charset="utf-8"><title>Test IdP</title>
<form method="get" action="approve">
{{range $k, $v := .}}<input type="hidden" name="{{$k}}" value="{{index $v 0}}">{{end}}
<label>Subject <input name="sub" required></label>
<button>Continue</button>
</form>`))

func (p *IdP) Mount(mux *http.ServeMux) {
	mux.HandleFunc("GET "+IdPPath+"/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, map[string]any{
			"issuer":                                p.issuer,
			"authorization_endpoint":                p.issuer + "/authorize",
			"token_endpoint":                        p.issuer + "/token",
			"jwks_uri":                              p.issuer + "/jwks",
			"response_types_supported":              []string{"code"},
			"subject_types_supported":               []string{"public"},
			"id_token_signing_alg_values_supported": []string{p.signer.Algorithm()},
			"code_challenge_methods_supported":      []string{"S256"},
		})
	})
	mux.HandleFunc("GET "+IdPPath+"/jwks", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, keys.JWKS{Keys: []keys.JWK{keys.PublicJWK(p.signer.Public(), p.signer.KID(), p.signer.Algorithm())}})
	})
	mux.HandleFunc("GET "+IdPPath+"/authorize", func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		if q.Get("client_id") != IdPClient || q.Get("response_type") != "code" || q.Get("redirect_uri") == "" {
			http.Error(w, "bad authorization request", http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_ = signInPage.Execute(w, url.Values{"state": {q.Get("state")}, "nonce": {q.Get("nonce")},
			"redirect_uri": {q.Get("redirect_uri")}, "code_challenge": {q.Get("code_challenge")}})
	})
	mux.HandleFunc("GET "+IdPPath+"/approve", func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		g := grant{Subject: strings.TrimSpace(q.Get("sub")), Nonce: q.Get("nonce"), RedirectURI: q.Get("redirect_uri"),
			CodeChallenge: q.Get("code_challenge"), AuthTime: time.Now().Unix()}
		target, err := url.Parse(g.RedirectURI)
		if err != nil || g.Subject == "" {
			http.Error(w, "bad sign-in", http.StatusBadRequest)
			return
		}
		raw, _ := json.Marshal(g)
		back := target.Query()
		back.Set("code", base64.RawURLEncoding.EncodeToString(raw))
		back.Set("state", q.Get("state"))
		target.RawQuery = back.Encode()
		http.Redirect(w, r, target.String(), http.StatusFound)
	})
	mux.HandleFunc("POST "+IdPPath+"/token", p.token)
}

func (p *IdP) token(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		oauthError(w, http.StatusBadRequest, "invalid_request")
		return
	}
	id, secret, ok := r.BasicAuth()
	if !ok {
		id, secret = r.PostForm.Get("client_id"), r.PostForm.Get("client_secret")
	}
	if id != IdPClient || subtle.ConstantTimeCompare([]byte(secret), []byte(IdPSecret)) != 1 {
		oauthError(w, http.StatusUnauthorized, "invalid_client")
		return
	}
	var g grant
	raw, err := base64.RawURLEncoding.DecodeString(r.PostForm.Get("code"))
	if err != nil || json.Unmarshal(raw, &g) != nil || g.RedirectURI != r.PostForm.Get("redirect_uri") {
		oauthError(w, http.StatusBadRequest, "invalid_grant")
		return
	}
	if g.CodeChallenge != "" {
		sum := sha256.Sum256([]byte(r.PostForm.Get("code_verifier")))
		if base64.RawURLEncoding.EncodeToString(sum[:]) != g.CodeChallenge {
			oauthError(w, http.StatusBadRequest, "invalid_grant")
			return
		}
	}
	now := time.Now()
	idToken, err := p.sign(r.Context(), map[string]any{"iss": p.issuer, "sub": g.Subject, "aud": IdPClient,
		"iat": now.Unix(), "exp": now.Add(5 * time.Minute).Unix(), "nonce": g.Nonce, "auth_time": g.AuthTime})
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, map[string]any{"access_token": "idp-access", "token_type": "Bearer", "expires_in": 300, "id_token": idToken})
}

func (p *IdP) sign(ctx context.Context, claims map[string]any) (string, error) {
	header, _ := json.Marshal(map[string]string{"alg": p.signer.Algorithm(), "kid": p.signer.KID(), "typ": "JWT"})
	body, _ := json.Marshal(claims)
	input := base64.RawURLEncoding.EncodeToString(header) + "." + base64.RawURLEncoding.EncodeToString(body)
	sig, err := p.signer.Sign(ctx, []byte(input))
	if err != nil {
		return "", err
	}
	return input + "." + base64.RawURLEncoding.EncodeToString(sig), nil
}

func oauthError(w http.ResponseWriter, status int, code string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": code})
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}
