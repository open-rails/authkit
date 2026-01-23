package oidckit

import (
	"context"
	"fmt"

	"github.com/zitadel/oidc/v2/pkg/client/rp"
	"github.com/zitadel/oidc/v2/pkg/oidc"
	"golang.org/x/oauth2"
)

// DefaultExchanger exchanges an authorization code using PKCE and extracts minimal claims.
func DefaultExchanger(ctx context.Context, rpClient rp.RelyingParty, provider, code, verifier, nonce string) (Claims, error) {
	// The RP client's built-in verifier doesn't know about our per-request nonce.
	// We need to: 1) Exchange code for tokens, 2) Manually verify ID token with custom verifier

	// Step 1: Exchange authorization code for tokens using OAuth2 directly (no ID token verification)
	oauthConfig := rpClient.OAuthConfig()

	// Add PKCE verifier to the token exchange
	var opts []oauth2.AuthCodeOption
	if provider != "apple" {
		opts = append(opts, oauth2.SetAuthURLParam("code_verifier", verifier))
	}

	oauth2Token, err := oauthConfig.Exchange(ctx, code, opts...)
	if err != nil {
		return Claims{}, fmt.Errorf("token exchange failed for %s: %w", provider, err)
	}

	rawIDToken, ok := oauth2Token.Extra("id_token").(string)
	if !ok || rawIDToken == "" {
		return Claims{}, fmt.Errorf("no id_token in response")
	}

	customVerifier := rp.NewIDTokenVerifier(
		rpClient.IDTokenVerifier().Issuer(),
		rpClient.IDTokenVerifier().ClientID(),
		rpClient.IDTokenVerifier().KeySet(),
		rp.WithNonce(func(context.Context) string { return nonce }),
	)

	idTokenClaims, err := rp.VerifyIDToken[*oidc.IDTokenClaims](ctx, rawIDToken, customVerifier)
	if err != nil {
		return Claims{}, fmt.Errorf("id_token verification with nonce failed for %s: %w", provider, err)
	}

	idt := idTokenClaims
	if idt == nil {
		return Claims{}, fmt.Errorf("missing id_token claims")
	}
	sub := idt.GetSubject()
	// Extract common fields from claims map if present
	var email string
	var ev bool
	if idt.UserInfoEmail.Email != "" {
		email = idt.UserInfoEmail.Email
		ev = bool(idt.UserInfoEmail.EmailVerified)
	}
	name := idt.UserInfoProfile.Name
	// Try to capture preferred_username if present
	var pu *string
	if idt.PreferredUsername != "" {
		pu = &idt.PreferredUsername
	}
	return Claims{Subject: sub, Email: strptr(email), EmailVerified: boolptr(ev), Name: strptr(name), PreferredUsername: pu, RawIDToken: rawIDToken}, nil
}

func strptr(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}
func boolptr(b bool) *bool { return &b }
