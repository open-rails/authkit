package authtest

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"encoding/base32"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/open-rails/authkit"
	"github.com/open-rails/authkit/devicekey"
	"github.com/open-rails/authkit/iam"
)

// Password is the password NewUser gives every account.
const Password = "Authtest-password-1"

// User is an account and what SignIn needs to sign it in.
type User struct {
	iam.User
	Password string
	// TOTP is the authenticator app SignIn answers a second-factor challenge
	// with; EnrollTOTP returns it.
	TOTP *TOTP
}

var users atomic.Int64

// NewUser creates an account with a verified email, a username and Password,
// as the host's own code would (Client.CreateUser).
func NewUser(t testing.TB, auth *authkit.Client) User {
	t.Helper()
	name := fmt.Sprintf("user%04d", users.Add(1))
	u, err := auth.CreateUser(context.Background(), iam.NewUser{Email: name + "@example.com", Username: name, Password: Password, EmailVerified: true})
	if err != nil {
		t.Fatalf("authtest: create user: %v", err)
	}
	return User{User: u, Password: Password}
}

// SignIn signs u in with its password through auth's HTTP surface and, when
// the account has a second factor, answers it with u.TOTP. It returns the
// session's tokens.
func SignIn(t testing.TB, auth *authkit.Client, u User) iam.TokenSet {
	t.Helper()
	identifier := u.Email
	if identifier == "" {
		identifier = u.Username
	}
	status, body := call(t, auth, http.MethodPost, "/password/login", "", map[string]string{"identifier": identifier, "password": u.Password})
	if status == http.StatusForbidden {
		var continuation struct {
			Error struct {
				Code     string `json:"code"`
				Metadata struct {
					UserID    string `json:"user_id"`
					Challenge string `json:"challenge"`
				} `json:"metadata"`
			} `json:"error"`
		}
		_ = json.Unmarshal(body, &continuation)
		if continuation.Error.Code == "2fa_required" {
			if u.TOTP == nil {
				t.Fatalf("authtest: %s needs a second factor and has no TOTP", identifier)
			}
			status, body = call(t, auth, http.MethodPost, "/2fa/verify", "", map[string]string{
				"user_id": continuation.Error.Metadata.UserID, "challenge": continuation.Error.Metadata.Challenge, "code": u.TOTP.Code(t)})
		}
	}
	if status != http.StatusOK {
		t.Fatalf("authtest: sign in %s: %d %s", identifier, status, body)
	}
	var session struct {
		iam.TokenSet
		Nested *iam.TokenSet `json:"token_set"`
	}
	if err := json.Unmarshal(body, &session); err != nil {
		t.Fatalf("authtest: sign in %s: %v", identifier, err)
	}
	if session.Nested != nil {
		return *session.Nested
	}
	return session.TokenSet
}

// GrantRole gives subject role in group with system authority. A role that
// requires MFA needs the account's second factor first (EnrollTOTP).
func GrantRole(t testing.TB, auth *authkit.Client, group iam.GroupRef, subject iam.Subject, role iam.Role) {
	t.Helper()
	if _, err := auth.SetGroupRole(context.Background(), iam.SystemActor(), group, subject, role); err != nil {
		t.Fatalf("authtest: grant %v to %s: %v", role, subject.ID, err)
	}
}

// RevokeRole takes role in group from subject with system authority.
func RevokeRole(t testing.TB, auth *authkit.Client, group iam.GroupRef, subject iam.Subject, role iam.Role) {
	t.Helper()
	if err := auth.RemoveGroupMember(context.Background(), iam.SystemActor(), group, subject, authkit.IfRole(role)); err != nil {
		t.Fatalf("authtest: revoke %v from %s: %v", role, subject.ID, err)
	}
}

// TOTP is an authenticator app enrolled on an account.
type TOTP struct {
	Secret string

	mu   sync.Mutex
	step int64 // the newest time step AuthKit has accepted
}

// Code returns a code AuthKit has not accepted yet. AuthKit takes each 30s
// step once, and at most one step ahead, so Code waits for the clock when
// both usable steps are spent.
func (a *TOTP) Code(t testing.TB) string {
	t.Helper()
	a.mu.Lock()
	defer a.mu.Unlock()
	step := max(a.step+1, time.Now().Unix()/30)
	if wait := time.Until(time.Unix((step-1)*30, 0)); wait > 0 {
		time.Sleep(wait)
	}
	a.step = step
	return TOTPCode(t, a.Secret, time.Unix(step*30, 0))
}

// TOTPCode is the RFC 6238 code of secret (base32) at the given time: SHA-1,
// six digits, 30-second steps.
func TOTPCode(t testing.TB, secret string, at time.Time) string {
	t.Helper()
	key, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(strings.ToUpper(strings.TrimSpace(secret)))
	if err != nil {
		t.Fatalf("authtest: TOTP secret: %v", err)
	}
	var counter [8]byte
	binary.BigEndian.PutUint64(counter[:], uint64(at.Unix()/30))
	mac := hmac.New(sha1.New, key)
	mac.Write(counter[:])
	sum := mac.Sum(nil)
	off := sum[len(sum)-1] & 0x0f
	return fmt.Sprintf("%06d", (binary.BigEndian.Uint32(sum[off:off+4])&0x7fffffff)%1000000)
}

// EnrollTOTP signs u in and adds an authenticator app through auth's HTTP
// surface, as a user would. Keep the result as u.TOTP so SignIn can answer the
// second factor it now requires.
func EnrollTOTP(t testing.TB, auth *authkit.Client, u User) *TOTP {
	t.Helper()
	token := SignIn(t, auth, u).AccessToken
	status, body := call(t, auth, http.MethodPost, "/user/2fa", token, map[string]string{"method": "totp"})
	var started struct {
		Secret string `json:"secret"`
	}
	if status != http.StatusOK || json.Unmarshal(body, &started) != nil || started.Secret == "" {
		t.Fatalf("authtest: start TOTP for %s: %d %s", u.Email, status, body)
	}
	app := &TOTP{Secret: started.Secret}
	status, body = call(t, auth, http.MethodPost, "/user/2fa", token, map[string]string{"method": "totp", "code": app.Code(t)})
	if status != http.StatusOK {
		t.Fatalf("authtest: confirm TOTP for %s: %d %s", u.Email, status, body)
	}
	return app
}

// DeviceKey is a device key enrolled on an account (see package devicekey).
type DeviceKey struct {
	ID  string
	Key ed25519.PrivateKey
	// AccessToken is the enrollment's sign-in.
	AccessToken string
}

// EnrollDeviceKey enrolls a new Ed25519 device key on u with the devicekey
// client, reading the emailed code from outbox and answering a second factor
// with u.TOTP. The Client needs Config.DeviceKeys.Enabled.
func EnrollDeviceKey(t testing.TB, auth *authkit.Client, outbox *Outbox, u User) DeviceKey {
	t.Helper()
	ctx := context.Background()
	c, err := devicekey.NewClient("http://authtest"+apiPath(t, auth), &http.Client{Transport: handlerTransport{auth.Handler()}})
	if err != nil {
		t.Fatalf("authtest: device-key client: %v", err)
	}
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	e, err := c.BeginEnrollment(ctx, u.Email, pub, "authtest")
	if err != nil {
		t.Fatalf("authtest: begin device-key enrollment for %s: %v", u.Email, err)
	}
	code := outbox.Last(t, iam.MessageVerification, u.Email).Code
	s, err := c.FinishEnrollment(ctx, e, priv, code, "")
	if second := (*devicekey.SecondFactorRequired)(nil); errors.As(err, &second) && second.Method == "totp" && u.TOTP != nil {
		s, err = c.FinishEnrollment(ctx, e, priv, code, u.TOTP.Code(t))
	}
	if err != nil {
		t.Fatalf("authtest: finish device-key enrollment for %s: %v", u.Email, err)
	}
	return DeviceKey{ID: s.DeviceKey.ID, Key: priv, AccessToken: s.AccessToken}
}

// call sends a JSON request to auth's API in process.
func call(t testing.TB, auth *authkit.Client, method, path, token string, body any) (int, []byte) {
	t.Helper()
	raw, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	r, err := http.NewRequest(method, "http://authtest"+apiPath(t, auth)+path, bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	r.Header.Set("Content-Type", "application/json")
	if token != "" {
		r.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := handlerTransport{auth.Handler()}.RoundTrip(r)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	out, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, out
}

// apiPath is the JSON API's mount path, found from the password sign-in route.
func apiPath(t testing.TB, auth *authkit.Client) string {
	t.Helper()
	for _, route := range auth.Routes() {
		if api, ok := strings.CutSuffix(route.Path, "/password/login"); ok && route.Method == http.MethodPost {
			return api
		}
	}
	t.Fatal("authtest: the Client serves no password sign-in route (Config.HTTP)")
	return ""
}

// handlerTransport serves requests with an http.Handler in process, from one
// fixed client address.
type handlerTransport struct{ h http.Handler }

func (tr handlerTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	if r.Body != nil {
		defer r.Body.Close()
	}
	if tr.h == nil {
		return nil, errors.New("authtest: the Client has no HTTP surface")
	}
	in := r.Clone(r.Context())
	in.RemoteAddr, in.RequestURI = "192.0.2.1:1234", r.URL.RequestURI()
	w := httptest.NewRecorder()
	tr.h.ServeHTTP(w, in)
	return w.Result(), nil
}
