package authcore

import (
	"context"
	"crypto"
	"net"
	"testing"

	"github.com/open-rails/authkit/jwtkit"
	"github.com/stretchr/testify/require"
)

// #288/14: outside dev the registration fetch dials through guardedDialContext,
// which resolves the domain itself and refuses any private/reserved answer —
// so a public name that resolves to loopback, RFC1918 or the cloud metadata
// address never gets a connection. Schemes, IP literals and non-public names
// are refused earlier and never reach the resolver.
func TestRegisterApplicationFromDomainGuardsDialOutsideDev(t *testing.T) {
	pool := testPG(t)
	ctx := context.Background()
	signer, err := jwtkit.NewRSASigner(2048, "ssrf-kid")
	require.NoError(t, err)
	svc, err := NewFromConfig(Config{
		Environment:  "production",
		Token:        TokenConfig{Issuer: "https://ssrf.example.com", IssuedAudiences: []string{"app"}, ExpectedAudiences: []string{"app"}},
		Keys:         KeysConfig{Source: jwtkit.StaticKeySource{Active: signer, Pubs: map[string]crypto.PublicKey{"ssrf-kid": signer.PublicKey()}}},
		RBAC:         []PersonaDef{{Name: "org", Parent: RootPersona}},
		Applications: ApplicationsConfig{SelfRegistration: true, OrgPersona: "org"},
	}, pool)
	require.NoError(t, err)

	prev := lookupIPAddr
	t.Cleanup(func() { lookupIPAddr = prev })

	var resolved []string
	for name, ip := range map[string]string{"loopback": "127.0.0.1", "rfc1918": "10.0.0.5", "metadata": "169.254.169.254"} {
		t.Run(name, func(t *testing.T) {
			lookupIPAddr = func(_ context.Context, host string) ([]net.IPAddr, error) {
				resolved = append(resolved, host)
				return []net.IPAddr{{IP: net.ParseIP(ip)}}, nil
			}
			_, err := svc.RegisterApplicationFromDomain(ctx, "app.example")
			require.ErrorIs(t, err, ErrApplicationDocumentFetchFailed)
			require.Contains(t, err.Error(), "private/reserved IP "+ip)
		})
	}
	require.Equal(t, []string{"app.example", "app.example", "app.example"}, resolved, "the guard resolves the registration domain itself")

	lookupIPAddr = func(_ context.Context, host string) ([]net.IPAddr, error) {
		t.Fatalf("resolver consulted for %q: the domain must be refused before any dial", host)
		return nil, nil
	}
	for _, domain := range []string{"http://app.example", "https://app.example", "localhost", "127.0.0.1", "169.254.169.254", "app", "app.example/path"} {
		_, err := svc.RegisterApplicationFromDomain(ctx, domain)
		require.ErrorIs(t, err, ErrApplicationDomainInvalid, domain)
	}
}
