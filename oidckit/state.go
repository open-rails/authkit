// Package oidckit holds the browser-flow state shared by authhttp and its
// ephemeral stores: the pending-login record, its cache contract, and PKCE
// generation. Providers themselves live in authprovider.
package oidckit

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"time"
)

// GeneratePKCE returns a verifier and S256 challenge suitable for the auth request.
func GeneratePKCE() (verifier string, challenge string, err error) {
	v := make([]byte, 32)
	if _, err = rand.Read(v); err != nil {
		return "", "", err
	}
	verifier = base64.RawURLEncoding.EncodeToString(v)
	sum := sha256.Sum256([]byte(verifier))
	challenge = base64.RawURLEncoding.EncodeToString(sum[:])
	return verifier, challenge, nil
}

// StateCache stores ephemeral OIDC state/PKCE data (backed by Redis in the app).
type StateCache interface {
	Put(ctx context.Context, state string, data StateData) error
	Get(ctx context.Context, state string) (StateData, bool, error)
	Del(ctx context.Context, state string) error
}

// StateData is what we persist for a pending OIDC login.
type StateData struct {
	Provider           string
	Verifier           string
	Nonce              string
	RedirectURI        string
	LinkUserID         string
	ReturnTo           string
	AccountInviteToken string
	// StepUp* fields identify a step-up authentication flow for an existing
	// session. Login/link flows leave these empty.
	StepUpUserID    string
	StepUpSessionID string
	StepUpReturnTo  string
	StepUpStartedAt time.Time
	UI              string // "popup" to trigger popup HTML callback; else redirect
	PopupNonce      string // echoed in popup postMessage for opener validation
}
