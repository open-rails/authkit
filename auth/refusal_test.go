package auth_test

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/open-rails/authkit/auth"
)

func TestRefuse(t *testing.T) {
	bearer, dpop, anonymous := "Bearer t", "DPoP t", ""
	cause := errors.New("provider detail")
	for _, c := range []struct {
		name, authorization string
		err                 error
		status              int
		challenge           string
	}{
		{"no error is a fault", bearer, nil, 503, ""},
		{"unclassified", bearer, cause, 503, ""},
		{"unavailable outranks the rest", bearer, errors.Join(auth.ErrUnavailable, auth.ErrUnauthenticated), 503, ""},
		{"anonymous", anonymous, auth.ErrUnauthenticated, 401, "Bearer"},
		{"invalid", bearer, errors.Join(auth.ErrUnauthenticated, cause), 401, `Bearer error="invalid_token"`},
		{"expired alone", bearer, auth.ErrExpired, 401, `Bearer error="invalid_token"`},
		{"revoked", bearer, errors.Join(auth.ErrUnauthenticated, auth.ErrRevoked), 401, `Bearer error="invalid_token"`},
		{"DPoP-bound", dpop, errors.Join(auth.ErrUnauthenticated, auth.ErrExpired), 401, `DPoP error="invalid_token"`},
		{"sender proof", dpop, errors.Join(auth.ErrUnauthenticated, auth.ErrSenderProofRequired), 401, `DPoP error="invalid_dpop_proof"`},
		{"forbidden", bearer, errors.Join(auth.ErrForbidden, cause), 403, ""},
		{"step-up", bearer, auth.ErrStepUpRequired, 401, `Bearer error="insufficient_user_authentication"`},
		{"step-up with max_age", bearer, &auth.Challenge{Err: auth.ErrStepUpRequired, MaxAge: 15 * time.Minute}, 401, `Bearer error="insufficient_user_authentication", max_age="900"`},
		{"max_age rounds up", dpop, &auth.Challenge{Err: auth.ErrStepUpRequired, MaxAge: 1500 * time.Millisecond}, 401, `DPoP error="insufficient_user_authentication", max_age="2"`},
		{"a challenge without a class", bearer, &auth.Challenge{}, 503, ""},
		{"the provider's challenge wins", dpop, &auth.Challenge{Err: auth.ErrSenderProofRequired, Header: http.Header{"WWW-Authenticate": {`DPoP error="use_dpop_nonce"`}}}, 401, `DPoP error="use_dpop_nonce"`},
	} {
		t.Run(c.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodGet, "https://billing.example/v1/me", nil)
			if c.authorization != "" {
				r.Header.Set("Authorization", c.authorization)
			}
			got := auth.Refuse(r, c.err)
			if got.Status != c.status || got.Header.Get("WWW-Authenticate") != c.challenge {
				t.Fatalf("got %d %q, want %d %q", got.Status, got.Header.Get("WWW-Authenticate"), c.status, c.challenge)
			}
		})
	}
}

func TestRefuseCarriesTheProvidersDetail(t *testing.T) {
	methods := map[string]any{"step_up_methods": []string{"password"}}
	err := errors.Join(errors.New("wrapped"), &auth.Challenge{
		Err:      auth.ErrStepUpRequired,
		Header:   http.Header{"dpop-nonce": {"n-1"}},
		Metadata: methods,
	})
	got := auth.Refuse(nil, err)
	if got.Status != 401 || got.Header.Get("DPoP-Nonce") != "n-1" || got.Metadata["step_up_methods"] == nil {
		t.Fatalf("%+v", got)
	}
	if !errors.Is(err, auth.ErrStepUpRequired) {
		t.Fatal("errors.Is does not see through Challenge")
	}
}
