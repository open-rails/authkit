package devicekey

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/open-rails/authkit/iam"
)

// maxAnswer bounds a success body; error bodies are bounded by iam.DecodeError.
const maxAnswer = 1 << 20

// Client speaks the device-key protocol to one AuthKit mount. A refusal is an
// iam.Error decoded from AuthKit's error envelope (iam.AsError, errors.Is
// against the iam sentinels); a device-key route answers 404 with no code when
// the host has not enabled device keys.
type Client struct {
	base string
	http *http.Client
}

// NewClient returns a Client for the AuthKit JSON API at baseURL: the mount's
// origin and API prefix, such as "https://example.com/api/v1". A nil hc uses
// http.DefaultClient.
func NewClient(baseURL string, hc *http.Client) (*Client, error) {
	baseURL = strings.TrimRight(strings.TrimSpace(baseURL), "/")
	u, err := url.Parse(baseURL)
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" || u.User != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" {
		return nil, fmt.Errorf("devicekey: %q is not an http(s) API URL", baseURL)
	}
	if hc == nil {
		hc = http.DefaultClient
	}
	return &Client{base: baseURL, http: hc}, nil
}

// BeginEnrollment asks AuthKit to email a code to email for enrolling key.
// label names the machine to the account owner (at most 128 bytes). A new
// address creates the account where registration is open.
func (c *Client) BeginEnrollment(ctx context.Context, email string, key ed25519.PublicKey, label string) (Enrollment, error) {
	if len(key) != ed25519.PublicKeySize {
		return Enrollment{}, errors.New("devicekey: the public key is not Ed25519")
	}
	req := struct {
		Email     string `json:"email"`
		PublicKey string `json:"public_key"`
		Label     string `json:"label,omitempty"`
	}{email, base64.RawURLEncoding.EncodeToString(key), label}
	var out struct {
		ID        string    `json:"enrollment_id"`
		Challenge string    `json:"challenge"`
		ExpiresAt time.Time `json:"expires_at"`
	}
	if err := c.do(ctx, http.MethodPost, "/device-keys/enroll/begin", "", req, &out); err != nil {
		return Enrollment{}, err
	}
	if out.ID == "" || !validChallenge(out.Challenge) {
		return Enrollment{}, malformed("/device-keys/enroll/begin")
	}
	return Enrollment{ID: out.ID, Challenge: out.Challenge, PublicKey: slices.Clone(key), ExpiresAt: out.ExpiresAt}, nil
}

// FinishEnrollment proves the emailed code and possession of key (the
// enrollment's key), enrolls it and signs it in. secondFactor is "" until a
// *SecondFactorRequired asks for one. The session's token also proves the
// account's email, which RevokeOthers requires: re-enrolling a key already
// enrolled on the account is how a machine obtains that proof.
func (c *Client) FinishEnrollment(ctx context.Context, e Enrollment, key crypto.Signer, code, secondFactor string) (Session, error) {
	if !isEd25519(key) || !key.Public().(ed25519.PublicKey).Equal(e.PublicKey) {
		return Session{}, errors.New("devicekey: the key is not the enrollment's key")
	}
	sig, err := SignEnrollment(key, e.Challenge)
	if err != nil {
		return Session{}, err
	}
	req := struct {
		EnrollmentID string `json:"enrollment_id"`
		Code         string `json:"code"`
		Signature    string `json:"signature"`
		SecondFactor string `json:"code_2fa,omitempty"`
	}{e.ID, strings.TrimSpace(code), sig, strings.TrimSpace(secondFactor)}
	started := time.Now()
	var out tokenAnswer
	if err := c.do(ctx, http.MethodPost, "/device-keys/enroll/finish", "", req, &out); err != nil {
		if ae, ok := iam.AsError(err); ok && ae.Code() == "step_up_required" {
			method, _ := ae.Metadata()["method"].(string)
			return Session{}, &SecondFactorRequired{Method: method, err: err}
		}
		return Session{}, err
	}
	return out.session("/device-keys/enroll/finish", started)
}

// Login signs in with the enrolled key id and its private key.
func (c *Client) Login(ctx context.Context, id string, key crypto.Signer) (Session, error) {
	var begun struct {
		ID        string `json:"challenge_id"`
		Challenge string `json:"challenge"`
	}
	if err := c.do(ctx, http.MethodPost, "/device-keys/login/begin", "", map[string]string{"device_key_id": id}, &begun); err != nil {
		return Session{}, err
	}
	if begun.ID == "" || !validChallenge(begun.Challenge) {
		return Session{}, malformed("/device-keys/login/begin")
	}
	sig, err := SignLogin(key, begun.Challenge)
	if err != nil {
		return Session{}, err
	}
	started := time.Now()
	var out tokenAnswer
	if err := c.do(ctx, http.MethodPost, "/device-keys/login/finish", "", map[string]string{"challenge_id": begun.ID, "signature": sig}, &out); err != nil {
		return Session{}, err
	}
	s, err := out.session("/device-keys/login/finish", started)
	if err == nil && s.DeviceKey.ID != id {
		return Session{}, malformed("/device-keys/login/finish")
	}
	return s, err
}

// List returns the account's device keys, revoked ones included, with a
// device-key access token.
func (c *Client) List(ctx context.Context, token string) ([]Key, error) {
	var out struct {
		Data []Key `json:"data"`
	}
	if err := c.do(ctx, http.MethodGet, "/device-keys", token, nil, &out); err != nil {
		return nil, err
	}
	return out.Data, nil
}

// Revoke revokes the account's key id with a device-key access token.
// Revoking the token's own key signs the machine out, and is retry-safe.
func (c *Client) Revoke(ctx context.Context, token, id string) error {
	return c.do(ctx, http.MethodDelete, "/device-keys/"+url.PathEscape(id), token, nil, nil)
}

// RevokeOthers revokes every key of the account but the token's own. The
// token must come from FinishEnrollment; a Login token is refused (forbidden).
func (c *Client) RevokeOthers(ctx context.Context, token string) error {
	return c.do(ctx, http.MethodPost, "/device-keys/revoke-others", token, struct{}{}, nil)
}

func (c *Client) do(ctx context.Context, method, path, token string, body, out any) error {
	var reader io.Reader
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			return err
		}
		reader = bytes.NewReader(raw)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.base+path, reader)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer func() {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, maxAnswer))
		_ = resp.Body.Close()
	}()
	if err := iam.DecodeError(resp); err != nil {
		return err
	}
	if out == nil {
		return nil
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxAnswer)).Decode(out); err != nil {
		return fmt.Errorf("devicekey: %s %s: unreadable answer: %w", method, path, err)
	}
	return nil
}

type tokenAnswer struct {
	TokenSet  iam.TokenSet `json:"token_set"`
	DeviceKey Key          `json:"device_key"`
}

// session dates the expiry from before the request, so latency never extends
// the server's lifetime.
func (a tokenAnswer) session(path string, started time.Time) (Session, error) {
	t := a.TokenSet
	if t.AccessToken == "" || !strings.EqualFold(t.TokenType, "Bearer") || t.ExpiresIn <= 0 || t.ExpiresIn > math.MaxInt64/int64(time.Second) || a.DeviceKey.ID == "" {
		return Session{}, malformed(path)
	}
	return Session{AccessToken: t.AccessToken, ExpiresAt: started.Add(time.Duration(t.ExpiresIn) * time.Second), DeviceKey: a.DeviceKey}, nil
}

func validChallenge(challenge string) bool {
	raw, err := base64.RawURLEncoding.DecodeString(challenge)
	return err == nil && len(raw) == challengeSize
}

func malformed(path string) error {
	return fmt.Errorf("devicekey: %s: malformed answer", path)
}
