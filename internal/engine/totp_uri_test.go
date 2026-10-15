package engine

import (
	"encoding/base32"
	"net/url"
	"strings"
	"testing"

	"github.com/open-rails/authkit/internal/config"
	"github.com/open-rails/authkit/internal/testdb"
)

func TestTOTPProvisioningLabels(t *testing.T) {
	secret, err := generateTOTPSecret()
	if err != nil {
		t.Fatal("generate fixture secret")
	}
	u, err := url.Parse(buildTOTPURI("http://localhost:2052", "reader@example.test", secret))
	if err != nil {
		t.Fatal("parse provisioning URI")
	}
	if u.Scheme != "otpauth" || u.Host != "totp" {
		t.Fatal("not a TOTP provisioning URI")
	}
	issuer, account, ok := strings.Cut(strings.TrimPrefix(u.Path, "/"), ":")
	if !ok || issuer != "localhost" || account != "reader@example.test" {
		t.Errorf("provisioning labels: issuer=%q account=%q", issuer, account)
	}
	q := u.Query()
	if q.Get("issuer") != issuer {
		t.Error("issuer query and label prefix differ")
	}
	if strings.ContainsAny(q.Get("issuer"), ":/") {
		t.Error("issuer label contains URL syntax")
	}
	if q.Get("digits") != "6" || q.Get("period") != "30" || q.Get("algorithm") != "SHA1" {
		t.Error("unexpected TOTP parameters")
	}
	raw, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(q.Get("secret"))
	if err != nil || len(raw) != totpSecretBytes {
		t.Error("invalid fixture secret encoding")
	}
}

func TestTOTPDisplayLabelsAndEncoding(t *testing.T) {
	for _, tc := range []struct{ issuer, account, wantIssuer, wantAccount string }{
		{"Doujins", "reader@example.test", "Doujins", "reader@example.test"},
		{"Hentai0", "reader+tag@example.test", "Hentai0", "reader+tag@example.test"},
		{"Example & Team", "reader:name", "Example & Team", "reader name"},
		{"例のサイト", "読者", "例のサイト", "読者"},
	} {
		u, err := url.Parse(buildTOTPURI(tc.issuer, tc.account, "JBSWY3DPEHPK3PXP"))
		if err != nil {
			t.Fatal("parse fixture URI")
		}
		issuer, account, ok := strings.Cut(strings.TrimPrefix(u.Path, "/"), ":")
		if !ok || issuer != tc.wantIssuer || account != tc.wantAccount || u.Query().Get("issuer") != issuer {
			t.Errorf("incorrect labels for %q", tc.issuer)
		}
	}
}

func TestTOTPEnrollmentUsesDisplayIssuer(t *testing.T) {
	pg := testdb.ScratchPostgres(t)
	cfg := testConfig()
	cfg.TwoFactor.TOTPIssuer = "Doujins"
	e := newTestEngine(t, cfg, config.Deps{Postgres: pg.Pool})
	u := newUser(t, e, "totp-label")
	_, uri, err := e.startTOTPEnrollment(t.Context(), u.ID)
	if err != nil {
		t.Fatal("start fixture enrollment:", err)
	}
	parsed, err := url.Parse(uri)
	if err != nil {
		t.Fatal("parse fixture URI")
	}
	if parsed.Query().Get("issuer") != "Doujins" || parsed.Path != "/Doujins:"+*u.Email {
		t.Fatal("enrollment did not use display issuer and account email")
	}
}

func TestTOTPDisplayIssuerValidation(t *testing.T) {
	for _, name := range []string{"https://example.test", "Service: Team", "Service\nName"} {
		cfg := testConfig()
		cfg.TwoFactor.TOTPIssuer = name
		if _, _, err := config.Normalize(cfg, config.Deps{}); err == nil {
			t.Errorf("accepted invalid display issuer %q", name)
		}
	}
}
