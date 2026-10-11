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
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/open-rails/authkit"
	"github.com/open-rails/authkit/devicekey"
	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/internal/httpapi"
	"github.com/open-rails/authkit/internal/testoutbox"
)

// Password is the password NewUser gives every account.
const Password = "Authtest-password-1"

// User is an account and what SignIn needs to sign it in. Email is the
// account's address as text ("" for none).
type User struct {
	iam.User
	Email    string
	Password string
	// TOTP is the authenticator app SignIn answers a second-factor challenge
	// with. Unset, SignIn uses the app EnrollTOTP or an earlier SignIn enrolled
	// on the account (TOTPOf).
	TOTP *TOTP
}

// NewUser creates an account with a verified email, a username and Password,
// as the host's own code would (Client.CreateUser). The username (user plus
// 16 random hex digits) and email are random, so test processes sharing one
// schema never collide.
func NewUser(t testing.TB, auth *authkit.Client) User {
	t.Helper()
	suffix := make([]byte, 8)
	_, _ = rand.Read(suffix)
	name := "user" + hex.EncodeToString(suffix)
	u, err := auth.CreateUser(context.Background(), iam.NewUser{Email: name + "@example.com", Username: name, Password: Password, EmailVerified: true})
	if err != nil {
		t.Fatalf("authtest: create user: %v", err)
	}
	return User{User: u, Email: name + "@example.com", Password: Password}
}

// SignIn signs u in with its password through auth's HTTP surface and follows
// the AuthResult to a session: a second factor is answered with u.TOTP (or
// the account's remembered app, TOTPOf); an enrollment the deployment
// requires adds an authenticator app with the enrollment token, which SignIn
// remembers for the account's later sign-ins; a new device's code (a
// phone-only account's every sign-in from here) is read from New's Outbox.
// It returns the session's tokens.
func SignIn(t testing.TB, auth *authkit.Client, u User) iam.TokenSet {
	t.Helper()
	identifier := u.Email
	if identifier == "" {
		identifier = u.Username
	}
	res := signInCall(t, auth, identifier, "/password/login", "", map[string]string{"identifier": identifier, "password": u.Password})
	for range 3 {
		switch res.Status {
		case httpapi.AuthComplete:
			remember(t, res.User.ID, u.TOTP)
			return *res.TokenSet
		case httpapi.AuthSecondFactorRequired:
			step := res.SecondFactor
			app := u.TOTP
			if app == nil {
				app = TOTPOf(step.UserID)
			}
			factorID := ""
			for _, f := range append([]httpapi.TwoFactorFactor{step.Factor}, step.Factors...) {
				if f.Method == "totp" {
					factorID = f.ID
				}
			}
			if app == nil || factorID == "" {
				t.Fatalf("authtest: %s needs a second factor and has no TOTP", identifier)
			}
			u.TOTP = app
			res = signInCall(t, auth, identifier, "/2fa/verify", "", map[string]string{"user_id": step.UserID, "challenge": step.Challenge, "factor_id": factorID, "code": app.Code(t)})
		case httpapi.AuthDeviceVerificationRequired:
			step := res.DeviceVerification
			res = signInCall(t, auth, identifier, "/device-verification/confirm", "", map[string]string{
				"user_id": step.UserID, "challenge": step.Challenge, "code": deviceCode(t, auth, step.UserID, u.Email)})
		case httpapi.AuthEnrollmentRequired:
			var created httpapi.TwoFactorFactorCreated
			u.TOTP, created = addTOTP(t, auth, identifier, res.Enrollment.TokenSet.AccessToken)
			if created.Auth == nil {
				t.Fatalf("authtest: enroll TOTP for %s: no sign-in", identifier)
			}
			res = *created.Auth
		default:
			t.Fatalf("authtest: sign in %s: %s", identifier, res.Status)
		}
	}
	t.Fatalf("authtest: sign in %s: no session", identifier)
	return iam.TokenSet{}
}

func signInCall(t testing.TB, auth *authkit.Client, identifier, path, token string, body any) httpapi.AuthResult {
	t.Helper()
	status, raw := call(t, auth, http.MethodPost, path, token, body)
	var res httpapi.AuthResult
	if status != http.StatusOK || json.Unmarshal(raw, &res) != nil {
		t.Fatalf("authtest: sign in %s: %s: %d %s", identifier, path, status, raw)
	}
	return res
}

// GrantRole gives subject role in group with system authority. A role that
// requires MFA needs the account's second factor first (EnrollTOTP).
func GrantRole(t testing.TB, auth *authkit.Client, group iam.GroupRef, subject iam.Subject, role iam.Role) {
	t.Helper()
	if _, err := auth.SetGroupRole(context.Background(), iam.SystemIdentity(), group, subject, role); err != nil {
		t.Fatalf("authtest: grant %v to %s: %v", role, subject.ID, err)
	}
}

// RevokeRole takes role in group from subject with system authority.
func RevokeRole(t testing.TB, auth *authkit.Client, group iam.GroupRef, subject iam.Subject, role iam.Role) {
	t.Helper()
	if err := auth.RemoveGroupMember(context.Background(), iam.SystemIdentity(), group, subject, authkit.IfRole(role)); err != nil {
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
// surface, as a user would. SignIn uses it from now on; keeping it as u.TOTP
// works too.
func EnrollTOTP(t testing.TB, auth *authkit.Client, u User) *TOTP {
	t.Helper()
	app, _ := addTOTP(t, auth, u.Email, SignIn(t, auth, u).AccessToken)
	remember(t, u.ID, app)
	return app
}

// addTOTP adds an authenticator app with token, a session's or an enrollment
// token: POST /me/2fa/setup, then /me/2fa/factors with its first code.
func addTOTP(t testing.TB, auth *authkit.Client, who, token string) (*TOTP, httpapi.TwoFactorFactorCreated) {
	t.Helper()
	status, body := call(t, auth, http.MethodPost, "/me/2fa/setup", token, map[string]string{"method": "totp"})
	var setup httpapi.TwoFactorSetup
	if status != http.StatusOK || json.Unmarshal(body, &setup) != nil || setup.Secret == nil || *setup.Secret == "" {
		t.Fatalf("authtest: start TOTP for %s: %d %s", who, status, body)
	}
	app := &TOTP{Secret: *setup.Secret}
	status, body = call(t, auth, http.MethodPost, "/me/2fa/factors", token, map[string]string{"method": "totp", "code": app.Code(t)})
	var created httpapi.TwoFactorFactorCreated
	if status != http.StatusCreated || json.Unmarshal(body, &created) != nil {
		t.Fatalf("authtest: confirm TOTP for %s: %d %s", who, status, body)
	}
	return app, created
}

var apps sync.Map // user id → *TOTP

// TOTPOf is the authenticator app EnrollTOTP or SignIn enrolled on the
// account userID; nil for none.
func TOTPOf(userID string) *TOTP {
	app, _ := apps.Load(userID)
	totp, _ := app.(*TOTP)
	return totp
}

func remember(t testing.TB, userID string, app *TOTP) {
	if userID == "" || app == nil {
		return
	}
	if _, loaded := apps.Swap(userID, app); !loaded {
		t.Cleanup(func() { apps.CompareAndDelete(userID, app) })
	}
}

// DeviceKey is a device key enrolled on an account (see package devicekey).
type DeviceKey struct {
	ID string
	// UserID is the account's.
	UserID string
	Key    ed25519.PrivateKey
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
	return DeviceKey{ID: s.DeviceKey.ID, UserID: u.ID, Key: priv, AccessToken: s.AccessToken}
}

// RevokeDeviceKey revokes k, as its machine signing out does: every
// capability it signed stops working.
func RevokeDeviceKey(t testing.TB, auth *authkit.Client, k DeviceKey) {
	t.Helper()
	c, err := devicekey.NewClient("http://authtest"+apiPath(t, auth), &http.Client{Transport: handlerTransport{auth.Handler()}})
	if err != nil {
		t.Fatalf("authtest: device-key client: %v", err)
	}
	if err := c.Logout(context.Background(), k.AccessToken); err != nil {
		t.Fatalf("authtest: revoke device key %s: %v", k.ID, err)
	}
}

// Capability is what a device key lets a workload do for its user
// (DeviceKey.Capability).
type Capability struct {
	// Audience is the resource server's identifier.
	Audience string
	// Workload is the key the capability is bound to (cnf.jkt).
	Workload *DPoPKey
	// AuthorizationDetails are the operations, an RFC 9396 JSON array.
	AuthorizationDetails string
	// Lifetime sets exp from now: 0 is one hour; a negative one makes an
	// expired capability.
	Lifetime time.Duration
	// ID (jti) is "" for a random one.
	ID string
	// Claims are other claims, such as the host's run id.
	Claims map[string]any
}

// Capability signs c with k for k's user, as a CLI does for a run
// (devicekey.SignCapability).
func (k DeviceKey) Capability(t testing.TB, c Capability) string {
	t.Helper()
	if c.Workload == nil {
		t.Fatalf("authtest: capability: a Workload key is required")
	}
	lifetime := c.Lifetime
	if lifetime == 0 {
		lifetime = time.Hour
	}
	now := time.Now()
	signed, err := devicekey.SignCapability(k.Key, k.ID, devicekey.Capability{
		UserID: k.UserID, Audience: c.Audience, WorkloadThumbprint: c.Workload.Thumbprint(),
		AuthorizationDetails: json.RawMessage(c.AuthorizationDetails), ID: c.ID,
		IssuedAt: now.Add(min(lifetime, 0)), ExpiresAt: now.Add(lifetime), Claims: c.Claims,
	})
	if err != nil {
		t.Fatalf("authtest: capability: %v", err)
	}
	return signed
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

// apiPath is the JSON API's mount path.
func apiPath(t testing.TB, auth *authkit.Client) string {
	t.Helper()
	api := auth.APIBase()
	if api == "" {
		t.Fatal("authtest: the Client serves no HTTP (Config.HTTP)")
	}
	return api
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

// deviceCode is the last new-device code auth sent userID (by SMS) or email,
// through New's Outbox.
func deviceCode(t testing.TB, auth *authkit.Client, userID, email string) string {
	t.Helper()
	_, deps := builtWith(t, auth)
	for _, sender := range []any{deps.SMS, deps.Email} {
		o := testoutbox.Of(sender)
		if o == nil {
			continue
		}
		msgs := o.Messages(iam.MessageNewDeviceCode, "")
		for i := len(msgs) - 1; i >= 0; i-- {
			if msgs[i].UserID == userID || email != "" && strings.EqualFold(msgs[i].To, email) {
				return msgs[i].Code
			}
		}
	}
	t.Fatalf("authtest: no new-device code for %s in the Outbox", userID)
	return ""
}
