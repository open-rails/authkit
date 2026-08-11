package authcore

// #264 unit tests: domain normalization, application.json validation, and
// per-message JWS verification — all DB-free (the DB-backed end-to-end flow
// lives in authhttp/application_registration_integration_test.go).

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	authkit "github.com/open-rails/authkit"
	"github.com/open-rails/authkit/jwtkit"
)

func newAppTestService(t *testing.T, env string) *Service {
	t.Helper()
	svc, err := NewFromConfig(Config{
		Environment: env,
		Keys:        KeysConfig{VerifyOnly: true},
		Token: TokenConfig{
			Issuer:            "https://hub.example.com",
			IssuedAudiences:   []string{"hub"},
			ExpectedAudiences: []string{"hub"},
		},
		RBAC: []PersonaDef{{Name: "org", Parent: RootPersona}},
		Applications: ApplicationsConfig{
			SelfRegistration: true,
			OrgPersona:       "org",
		},
	}, nil)
	require.NoError(t, err)
	return svc
}

func TestResolveApplicationDomain(t *testing.T) {
	dev := newAppTestService(t, "development")
	prod := newAppTestService(t, "production")

	t.Run("prod accepts bare public dns names only", func(t *testing.T) {
		canonical, host, fetchURL, err := prod.resolveApplicationDomain("Cozy.Art")
		require.NoError(t, err)
		require.Equal(t, "cozy.art", canonical)
		require.Equal(t, "cozy.art", host)
		require.Equal(t, "https://cozy.art"+ApplicationWellKnownPath, fetchURL)

		for _, bad := range []string{
			"", "http://cozy.art", "https://cozy.art", "cozy.art/path", "cozy.art:8443",
			"127.0.0.1", "10.0.0.4", "localhost", "metadata.google.internal",
			"host.docker.internal", "single-label", "co..zy.art", "-cozy.art",
		} {
			_, _, _, err := prod.resolveApplicationDomain(bad)
			require.ErrorIs(t, err, ErrApplicationDomainInvalid, "input %q", bad)
		}
	})

	t.Run("dev additionally accepts loopback base urls", func(t *testing.T) {
		canonical, host, fetchURL, err := dev.resolveApplicationDomain("http://127.0.0.1:8080")
		require.NoError(t, err)
		require.Equal(t, "http://127.0.0.1:8080", canonical, "dev canonical keeps scheme+port so distinct rigs stay distinct roots")
		require.Equal(t, "127.0.0.1", host)
		require.Equal(t, "http://127.0.0.1:8080"+ApplicationWellKnownPath, fetchURL)

		_, _, _, err = dev.resolveApplicationDomain("http://127.0.0.1:8080/some/path")
		require.ErrorIs(t, err, ErrApplicationDomainInvalid)
	})
}

func TestValidateApplicationDocument(t *testing.T) {
	dev := newAppTestService(t, "development")
	prod := newAppTestService(t, "production")

	base := func() *ApplicationDocument {
		return &ApplicationDocument{
			Slug:        "cozy.art",
			DisplayName: "  Cozy Art  ",
			Issuer:      "https://cozy.art",
			JWKSURI:     "https://cozy.art/.well-known/jwks.json",
		}
	}

	t.Run("valid document normalizes", func(t *testing.T) {
		got, err := prod.validateApplicationDocument(base(), "cozy.art")
		require.NoError(t, err)
		require.Equal(t, "cozy.art", got.Slug)
		require.Equal(t, "Cozy Art", got.DisplayName)
		require.Equal(t, RemoteAppModeJWKS, got.Mode)
	})

	t.Run("empty slug defaults to the proven host", func(t *testing.T) {
		doc := base()
		doc.Slug = ""
		got, err := prod.validateApplicationDocument(doc, "cozy.art")
		require.NoError(t, err)
		require.Equal(t, "cozy.art", got.Slug)
	})

	t.Run("slug is a free claim; issuer host is NOT", func(t *testing.T) {
		// Slugs and domains are separate: any valid slug may be requested.
		doc := base()
		doc.Slug = "cozy-creator"
		got, err := prod.validateApplicationDocument(doc, "cozy.art")
		require.NoError(t, err)
		require.Equal(t, "cozy-creator", got.Slug)

		// The issuer stays bound to the PROVEN domain (trust, not naming).
		doc = base()
		doc.Issuer = "https://evil.example/oidc"
		_, err = prod.validateApplicationDocument(doc, "cozy.art")
		require.ErrorIs(t, err, ErrApplicationDocumentInvalid)

		// Dev-like environments relax the issuer binding for loopback rigs.
		doc = base()
		doc.Slug = "rig-a"
		doc.Issuer = "http://127.0.0.1:9999"
		doc.JWKSURI = "http://127.0.0.1:9999/jwks.json"
		got, err = dev.validateApplicationDocument(doc, "127.0.0.1")
		require.NoError(t, err)
		require.Equal(t, "rig-a", got.Slug)
	})

	t.Run("platform issuer is reserved", func(t *testing.T) {
		doc := base()
		doc.Issuer = "https://hub.example.com"
		_, err := dev.validateApplicationDocument(doc, "cozy.art")
		require.ErrorIs(t, err, ErrReservedIssuer)
	})

	t.Run("exactly one trust source", func(t *testing.T) {
		doc := base()
		doc.PublicKeys = []authkit.RemoteAppKey{{KID: "k", PublicKeyPEM: "junk"}}
		_, err := prod.validateApplicationDocument(doc, "cozy.art")
		require.ErrorIs(t, err, ErrApplicationDocumentInvalid)

		doc = base()
		doc.JWKSURI = ""
		_, err = prod.validateApplicationDocument(doc, "cozy.art")
		require.ErrorIs(t, err, ErrApplicationDocumentInvalid)
	})
}

func TestRemoteAppSlugAllowsDomains(t *testing.T) {
	require.NoError(t, validateRemoteAppSlug("cozy.art"))
	require.NoError(t, validateRemoteAppSlug("api.eu-west.cozy.art"))
	require.Error(t, validateRemoteAppSlug("co..zy.art"))
	require.Error(t, validateRemoteAppSlug(".cozy.art"))
	require.Error(t, validateRemoteAppSlug("cozy.art."))
}

func pemForSigner(t *testing.T, signer *jwtkit.RSASigner) string {
	t.Helper()
	der, err := x509.MarshalPKIXPublicKey(signer.PublicKey())
	require.NoError(t, err)
	return string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))
}

func signAppRequest(t *testing.T, signer *jwtkit.RSASigner, typ string, payload map[string]any) string {
	t.Helper()
	raw, err := json.Marshal(payload)
	require.NoError(t, err)
	compact, err := jwtkit.SignPayloadWithType(context.Background(), signer, raw, typ)
	require.NoError(t, err)
	return compact
}

func TestVerifyApplicationJWS(t *testing.T) {
	svc := newAppTestService(t, "development")
	ctx := context.Background()

	signer, err := jwtkit.NewRSASigner(2048, "app-key-1")
	require.NoError(t, err)
	app := &RemoteApplication{
		Slug: "cozy.art",
		Mode: RemoteAppModeStatic,
		PublicKeys: []authkit.RemoteAppKey{
			{KID: "app-key-1", PublicKeyPEM: pemForSigner(t, signer)},
		},
		Enabled: true,
	}
	valid := func() map[string]any {
		return map[string]any{
			"op":   "rotate",
			"slug": "cozy.art",
			"aud":  "https://hub.example.com",
			"iat":  time.Now().Unix(),
			"public_keys": []map[string]string{
				{"kid": "app-key-2", "public_key_pem": pemForSigner(t, signer)},
			},
		}
	}

	t.Run("valid request verifies", func(t *testing.T) {
		req, err := svc.verifyApplicationJWS(ctx, app, signAppRequest(t, signer, applicationRequestJOSEType, valid()), "rotate")
		require.NoError(t, err)
		require.Equal(t, "cozy.art", req.Slug)
		require.Len(t, req.PublicKeys, 1)
	})

	t.Run("wrong JOSE typ rejected", func(t *testing.T) {
		_, err := svc.verifyApplicationJWS(ctx, app, signAppRequest(t, signer, "JOSE", valid()), "rotate")
		require.ErrorIs(t, err, ErrApplicationSignatureInvalid)
	})

	t.Run("stale iat rejected", func(t *testing.T) {
		p := valid()
		p["iat"] = time.Now().Add(-applicationJWSMaxSkew - time.Minute).Unix()
		_, err := svc.verifyApplicationJWS(ctx, app, signAppRequest(t, signer, applicationRequestJOSEType, p), "rotate")
		require.ErrorIs(t, err, ErrApplicationSignatureStale)
	})

	t.Run("wrong audience rejected", func(t *testing.T) {
		p := valid()
		p["aud"] = "https://other-platform.example"
		_, err := svc.verifyApplicationJWS(ctx, app, signAppRequest(t, signer, applicationRequestJOSEType, p), "rotate")
		require.ErrorIs(t, err, ErrApplicationSignatureInvalid)
	})

	t.Run("op and slug are bound", func(t *testing.T) {
		_, err := svc.verifyApplicationJWS(ctx, app, signAppRequest(t, signer, applicationRequestJOSEType, valid()), "repoint")
		require.ErrorIs(t, err, ErrApplicationSignatureInvalid)

		p := valid()
		p["slug"] = "evil.example"
		_, err = svc.verifyApplicationJWS(ctx, app, signAppRequest(t, signer, applicationRequestJOSEType, p), "rotate")
		require.ErrorIs(t, err, ErrApplicationSignatureInvalid)
	})

	t.Run("untrusted signer rejected", func(t *testing.T) {
		other, err := jwtkit.NewRSASigner(2048, "app-key-1") // same kid, different key
		require.NoError(t, err)
		_, err = svc.verifyApplicationJWS(ctx, app, signAppRequest(t, other, applicationRequestJOSEType, valid()), "rotate")
		require.ErrorIs(t, err, ErrApplicationSignatureInvalid)
	})

	t.Run("unknown kid rejected", func(t *testing.T) {
		strange, err := jwtkit.NewRSASigner(2048, "unknown-kid")
		require.NoError(t, err)
		_, err = svc.verifyApplicationJWS(ctx, app, signAppRequest(t, strange, applicationRequestJOSEType, valid()), "rotate")
		require.ErrorIs(t, err, ErrApplicationSignatureInvalid)
	})
}

func TestApplicationsConfigValidatedAtConstruction(t *testing.T) {
	_, err := NewFromConfig(Config{
		Keys:  KeysConfig{VerifyOnly: true},
		Token: TokenConfig{Issuer: "https://hub.example.com", IssuedAudiences: []string{"hub"}},
		Applications: ApplicationsConfig{
			SelfRegistration: true,
			OrgPersona:       "undeclared",
		},
	}, nil)
	require.Error(t, err)
	require.Contains(t, fmt.Sprint(err), "OrgPersona")
}
