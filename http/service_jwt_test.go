package authhttp

import (
	"context"
	"crypto"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	jwt "github.com/golang-jwt/jwt/v5"
	core "github.com/open-rails/authkit/core"
	jwtkit "github.com/open-rails/authkit/jwt"
	"github.com/stretchr/testify/require"
)

func newServiceJWTVerifier(t *testing.T, signer *jwtkit.RSASigner, issuer string, audiences []string) *Verifier {
	t.Helper()
	v := NewVerifier(WithSkew(time.Second))
	require.NoError(t, v.AddIssuer(issuer, audiences, IssuerOptions{
		RawKeys: map[string]crypto.PublicKey{signer.KID(): signer.PublicKey()},
		RemoteApplicationSlug: "hentai0",
	}))
	return v
}

func TestVerifyServiceJWTValidToken(t *testing.T) {
	signer, err := jwtkit.NewRSASigner(2048, "kid")
	require.NoError(t, err)
	issuer := "https://auth.hentai0.example"
	v := newServiceJWTVerifier(t, signer, issuer, []string{"openrails"})

	token, _, err := core.MintServiceJWT(context.Background(), signer, issuer, core.ServiceJWTMintOptions{
		Subject:     "service:hentai0-runtime",
		Audiences:   []string{"openrails"},
		Permissions: []string{"openrails:entitlements:read"},
		Resources:   []core.APIKeyResource{{Kind: "openrails.merchant", ID: "hentai0"}},
		JTI:         "jti-1",
	})
	require.NoError(t, err)

	claims, principal, err := v.VerifyServiceJWT(context.Background(), token)
	require.NoError(t, err)
	require.Equal(t, "service:hentai0-runtime", claims.Subject)
	require.Equal(t, "hentai0", principal.RemoteApplicationSlug)
	require.Equal(t, []string{"openrails:entitlements:read"}, principal.Permissions)
	require.Equal(t, []core.APIKeyResource{{Kind: "openrails.merchant", ID: "hentai0"}}, principal.Resources)
}

func TestVerifyServiceJWTRejections(t *testing.T) {
	signer, err := jwtkit.NewRSASigner(2048, "kid")
	require.NoError(t, err)
	issuer := "https://auth.hentai0.example"
	v := newServiceJWTVerifier(t, signer, issuer, []string{"openrails"})
	now := time.Now().UTC()

	t.Run("wrong audience", func(t *testing.T) {
		token, _, err := core.MintServiceJWT(context.Background(), signer, issuer, core.ServiceJWTMintOptions{
			Subject: "service:hentai0-runtime", Audiences: []string{"tensorhub"},
		})
		require.NoError(t, err)
		_, _, err = v.VerifyServiceJWT(context.Background(), token)
		require.EqualError(t, err, "bad_audience")
	})

	t.Run("expired", func(t *testing.T) {
		token, err := signer.Sign(context.Background(), jwt.MapClaims{
			"iss": issuer, "sub": "service:hentai0-runtime", "aud": "openrails",
			"iat": now.Add(-30 * time.Minute).Unix(), "nbf": now.Add(-30 * time.Minute).Unix(), "exp": now.Add(-time.Minute).Unix(),
			"jti": "expired", "token_use": core.ServiceJWTTokenUse, "permissions": []string{"openrails:entitlements:read"},
		})
		require.NoError(t, err)
		_, _, err = v.VerifyServiceJWT(context.Background(), token)
		require.EqualError(t, err, "token_expired")
	})

	t.Run("excessive lifetime", func(t *testing.T) {
		token, err := signer.Sign(context.Background(), jwt.MapClaims{
			"iss": issuer, "sub": "service:hentai0-runtime", "aud": "openrails",
			"iat": now.Unix(), "nbf": now.Unix(), "exp": now.Add(time.Hour).Unix(),
			"jti": "too-long", "token_use": core.ServiceJWTTokenUse, "permissions": []string{"openrails:entitlements:read"},
		})
		require.NoError(t, err)
		_, _, err = v.VerifyServiceJWT(context.Background(), token)
		require.EqualError(t, err, "service_jwt_lifetime_exceeded")
	})

	t.Run("missing token use", func(t *testing.T) {
		token, err := signer.Sign(context.Background(), jwt.MapClaims{
			"iss": issuer, "sub": "service:hentai0-runtime", "aud": "openrails",
			"iat": now.Unix(), "nbf": now.Unix(), "exp": now.Add(time.Minute).Unix(), "jti": "missing-use",
			"permissions": []string{"openrails:entitlements:read"},
		})
		require.NoError(t, err)
		_, _, err = v.VerifyServiceJWT(context.Background(), token)
		require.ErrorIs(t, err, core.ErrInvalidServiceJWT)
	})

	t.Run("wrong token use", func(t *testing.T) {
		token, err := signer.Sign(context.Background(), jwt.MapClaims{
			"iss": issuer, "sub": "service:hentai0-runtime", "aud": "openrails",
			"iat": now.Unix(), "nbf": now.Unix(), "exp": now.Add(time.Minute).Unix(), "jti": "wrong-use",
			"token_use": "access", "permissions": []string{"openrails:entitlements:read"},
		})
		require.NoError(t, err)
		_, _, err = v.VerifyServiceJWT(context.Background(), token)
		require.ErrorIs(t, err, core.ErrInvalidServiceJWT)
	})

	t.Run("malformed permissions", func(t *testing.T) {
		token, err := signer.Sign(context.Background(), jwt.MapClaims{
			"iss": issuer, "sub": "service:hentai0-runtime", "aud": "openrails",
			"iat": now.Unix(), "nbf": now.Unix(), "exp": now.Add(time.Minute).Unix(), "jti": "bad-perms",
			"token_use": core.ServiceJWTTokenUse, "permissions": "openrails:entitlements:read",
		})
		require.NoError(t, err)
		_, _, err = v.VerifyServiceJWT(context.Background(), token)
		require.EqualError(t, err, "malformed_permissions")
	})

	t.Run("bad signature", func(t *testing.T) {
		rogue, err := jwtkit.NewRSASigner(2048, "rogue")
		require.NoError(t, err)
		token, _, err := core.MintServiceJWT(context.Background(), rogue, issuer, core.ServiceJWTMintOptions{
			Subject: "service:hentai0-runtime", Audiences: []string{"openrails"},
		})
		require.NoError(t, err)
		_, _, err = v.VerifyServiceJWT(context.Background(), token)
		require.EqualError(t, err, "invalid_token")
	})

	t.Run("unknown issuer", func(t *testing.T) {
		token, _, err := core.MintServiceJWT(context.Background(), signer, "https://unknown.example", core.ServiceJWTMintOptions{
			Subject: "service:hentai0-runtime", Audiences: []string{"openrails"},
		})
		require.NoError(t, err)
		_, _, err = v.VerifyServiceJWT(context.Background(), token)
		require.EqualError(t, err, "invalid_token")
	})
}

func TestVerifyServiceJWTScopeCompatibilityAndReplayHook(t *testing.T) {
	signer, err := jwtkit.NewRSASigner(2048, "kid")
	require.NoError(t, err)
	issuer := "https://auth.hentai0.example"
	v := newServiceJWTVerifier(t, signer, issuer, []string{"openrails"})
	now := time.Now().UTC()

	token, err := signer.Sign(context.Background(), jwt.MapClaims{
		"iss": issuer, "sub": "service:hentai0-runtime", "aud": "openrails",
		"iat": now.Unix(), "nbf": now.Unix(), "exp": now.Add(time.Minute).Unix(),
		"jti": "scope-ok", "token_use": core.ServiceJWTTokenUse,
		"scope": "openrails:entitlements:read openrails:credits:reserve",
	})
	require.NoError(t, err)
	claims, principal, err := v.VerifyServiceJWT(context.Background(), token)
	require.NoError(t, err)
	require.Equal(t, []string{"openrails:entitlements:read", "openrails:credits:reserve"}, principal.Permissions)
	require.Equal(t, principal.Permissions, claims.Scope)

	replayErr := errors.New("replay")
	_, _, err = v.VerifyServiceJWT(context.Background(), token, WithServiceJWTReplayChecker(func(context.Context, core.ServiceJWTClaims) error {
		return replayErr
	}))
	require.ErrorIs(t, err, replayErr)
}

func TestRequiredServiceJWTMiddleware(t *testing.T) {
	signer, err := jwtkit.NewRSASigner(2048, "kid")
	require.NoError(t, err)
	issuer := "https://auth.hentai0.example"
	v := newServiceJWTVerifier(t, signer, issuer, []string{"openrails"})
	token, _, err := core.MintServiceJWT(context.Background(), signer, issuer, core.ServiceJWTMintOptions{
		Subject: "service:hentai0-runtime", Audiences: []string{"openrails"},
	})
	require.NoError(t, err)

	protected := RequiredServiceJWT(v)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		principal, ok := ServiceJWTPrincipalFromContext(r.Context())
		require.True(t, ok)
		require.Equal(t, "service:hentai0-runtime", principal.Subject)
		w.WriteHeader(http.StatusNoContent)
	}))
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	protected.ServeHTTP(rec, req)
	require.Equal(t, 204, rec.Code)
}

func TestWrongTokenTypeDenials(t *testing.T) {
	signer, err := jwtkit.NewRSASigner(2048, "kid")
	require.NoError(t, err)
	issuer := "https://auth.hentai0.example"
	v := newServiceJWTVerifier(t, signer, issuer, []string{"openrails"})
	now := time.Now().UTC()

	userToken, err := signer.SignWithHeaders(context.Background(), jwt.MapClaims{
		"iss": issuer,
		"sub": "user-1",
		"aud": "openrails",
		"iat": now.Unix(),
		"nbf": now.Unix(),
		"exp": now.Add(time.Minute).Unix(),
	}, map[string]any{"typ": AccessTokenType})
	require.NoError(t, err)

	delegatedToken, err := MintDelegatedAccessToken(context.Background(), signer, DelegatedAccessParams{
		Issuer: issuer, Audiences: []string{"openrails"},
		DelegatedSubject: "external-user-1", TTL: time.Minute,
	})
	require.NoError(t, err)

	serviceToken, _, err := core.MintServiceJWT(context.Background(), signer, issuer, core.ServiceJWTMintOptions{
		Subject: "service:hentai0-runtime", Audiences: []string{"openrails"}, JTI: "svc-denial",
	})
	require.NoError(t, err)

	t.Run("ordinary required rejects service jwt", func(t *testing.T) {
		protected := Required(v)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			t.Fatal("service JWT must not reach ordinary Required route")
		}))
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.Header.Set("Authorization", "Bearer "+serviceToken)
		rec := httptest.NewRecorder()
		protected.ServeHTTP(rec, req)
		require.Equal(t, http.StatusUnauthorized, rec.Code)
		requireErrorCode(t, rec.Body.String(), "access_token_wrong_typ")
	})

	t.Run("service required rejects user jwt", func(t *testing.T) {
		protected := RequiredServiceJWT(v)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			t.Fatal("user JWT must not reach service-JWT route")
		}))
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.Header.Set("Authorization", "Bearer "+userToken)
		rec := httptest.NewRecorder()
		protected.ServeHTTP(rec, req)
		require.Equal(t, http.StatusUnauthorized, rec.Code)
		requireErrorCode(t, rec.Body.String(), "invalid_service_jwt")
	})

	t.Run("service required rejects delegated jwt", func(t *testing.T) {
		protected := RequiredServiceJWT(v)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			t.Fatal("delegated JWT must not reach service-JWT route")
		}))
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.Header.Set("Authorization", "Bearer "+delegatedToken)
		rec := httptest.NewRecorder()
		protected.ServeHTTP(rec, req)
		require.Equal(t, http.StatusUnauthorized, rec.Code)
		requireErrorCode(t, rec.Body.String(), "invalid_service_jwt")
	})

	t.Run("delegated verifier rejects service jwt", func(t *testing.T) {
		_, _, err := v.VerifyDelegatedAccess(serviceToken)
		require.EqualError(t, err, "access_token_wrong_typ")
	})
}

func TestVerifyServiceJWTDisabledOrgIssuerFailsClosed(t *testing.T) {
	signer, err := jwtkit.NewRSASigner(2048, "kid")
	require.NoError(t, err)
	issuer := "https://disabled-issuer.example"
	token, _, err := core.MintServiceJWT(context.Background(), signer, issuer, core.ServiceJWTMintOptions{
		Subject: "service:disabled", Audiences: []string{"openrails"},
	})
	require.NoError(t, err)

	v := NewVerifier()
	src := disabledOrgIssuerSource{issuer: core.RemoteApplication{
		Slug: "hentai0", Issuer: issuer, JWKSURI: "https://disabled-issuer.example/jwks", Enabled: false,
	}}
	require.NoError(t, v.LoadRemoteApplications(context.Background(), src, []string{"openrails"}))
	_, _, err = v.VerifyServiceJWT(context.Background(), token)
	require.EqualError(t, err, "invalid_token")
}

type disabledOrgIssuerSource struct {
	issuer core.RemoteApplication
}

func (s disabledOrgIssuerSource) ListRemoteApplications(context.Context, bool) ([]core.RemoteApplication, error) {
	return nil, nil
}

func (s disabledOrgIssuerSource) GetRemoteApplication(_ context.Context, issuerID string) (*core.RemoteApplication, error) {
	if issuerID == s.issuer.Issuer {
		return &s.issuer, nil
	}
	return nil, core.ErrRemoteApplicationNotFound
}
