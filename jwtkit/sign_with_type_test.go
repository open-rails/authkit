package jwtkit

import (
	"context"
	"testing"

	jwt "github.com/golang-jwt/jwt/v5"
)

// plainTestSigner implements Signer but NOT HeaderSigner.
type plainTestSigner struct{ signCalls int }

func (p *plainTestSigner) Algorithm() string { return "test" }
func (p *plainTestSigner) KID() string       { return "k" }
func (p *plainTestSigner) Sign(context.Context, jwt.MapClaims) (string, error) {
	p.signCalls++
	return "plain-token", nil
}

// headerTestSigner implements HeaderSigner and records the headers it received.
type headerTestSigner struct {
	plainTestSigner
	lastHeaders map[string]any
}

func (h *headerTestSigner) SignWithHeaders(_ context.Context, _ jwt.MapClaims, headers map[string]any) (string, error) {
	h.lastHeaders = headers
	return "header-token", nil
}

func TestSignWithType(t *testing.T) {
	ctx := context.Background()
	claims := jwt.MapClaims{"sub": "u1"}

	t.Run("empty typ -> plain Sign, no header", func(t *testing.T) {
		hs := &headerTestSigner{}
		tok, err := SignWithType(ctx, hs, claims, "", true)
		if err != nil || tok != "plain-token" {
			t.Fatalf("got (%q,%v), want plain-token,nil", tok, err)
		}
		if hs.lastHeaders != nil {
			t.Fatalf("SignWithHeaders should not run for empty typ; headers=%v", hs.lastHeaders)
		}
	})

	t.Run("typ + HeaderSigner -> stamps typ", func(t *testing.T) {
		hs := &headerTestSigner{}
		tok, err := SignWithType(ctx, hs, claims, "access+jwt", true)
		if err != nil || tok != "header-token" {
			t.Fatalf("got (%q,%v), want header-token,nil", tok, err)
		}
		if hs.lastHeaders["typ"] != "access+jwt" {
			t.Fatalf("typ header=%v, want access+jwt", hs.lastHeaders["typ"])
		}
	})

	t.Run("typ + requireHeader + plain signer -> error", func(t *testing.T) {
		p := &plainTestSigner{}
		if _, err := SignWithType(ctx, p, claims, "access+jwt", true); err == nil {
			t.Fatal("want error when a non-HeaderSigner is required to stamp typ")
		}
		if p.signCalls != 0 {
			t.Fatalf("must not fall back to Sign when requireHeader=true; signCalls=%d", p.signCalls)
		}
	})

	t.Run("typ + !requireHeader + plain signer -> Sign fallback", func(t *testing.T) {
		p := &plainTestSigner{}
		tok, err := SignWithType(ctx, p, claims, "service+jwt", false)
		if err != nil || tok != "plain-token" {
			t.Fatalf("got (%q,%v), want plain-token,nil", tok, err)
		}
		if p.signCalls != 1 {
			t.Fatalf("want one Sign fallback call; signCalls=%d", p.signCalls)
		}
	})
}
