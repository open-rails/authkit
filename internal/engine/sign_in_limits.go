package engine

// Sign-in limits (Config.SignIn, ak#429): distinct accounts per device and
// new devices per account over a rolling 24 hours. Both are counted in the
// shared ephemeral store under keys and members that are hashes of the
// device and the account together, so the store never lists which accounts
// share a device: reading that back needs the device's own cookie.

import (
	"context"
	"slices"
	"strings"
	"time"

	jwt "github.com/golang-jwt/jwt/v5"

	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/internal/authflow"
	"github.com/open-rails/authkit/internal/db"
	"github.com/open-rails/authkit/internal/errmodel"
	"github.com/open-rails/authkit/internal/secret"
)

const (
	signInWindow      = 24 * time.Hour
	knownDeviceWindow = 30 * 24 * time.Hour
	// maxKnownDevices bounds one account's record; the least recently seen
	// go first.
	maxKnownDevices = 256
	// maxDeviceCodesPerHour bounds the codes one account is sent, so a
	// posted password cannot flood the owner's inbox.
	maxDeviceCodesPerHour = 10

	keySignInDevice   = "signin:device:"      // +digest(device) -> deviceAccounts
	keySignInAccount  = "signin:account:"     // +<userID> -> accountDevices
	keyDeviceCode     = "signin:device-code:" // +<userID>:<proof nonce hash>
	keyDeviceCodeSent = "signin:device-sent:" // +<userID>, hourly send count
)

// deviceAccounts is one device's accounts: digest(device, account) -> the
// unix second of its latest sign-in.
type deviceAccounts map[string]int64

// accountDevices is one account's devices: digest(account, device) -> when
// it was last seen, and when it was counted as new (0: it came in beside a
// counted one, as a browser's first device cookie does).
type accountDevices map[string]accountDevice

type accountDevice struct {
	Seen int64 `json:"s"`
	New  int64 `json:"n,omitempty"`
}

func digest(parts ...string) string {
	return secret.Hash(strings.Join(parts, "\x00"))[:32]
}

func signInLimit(code errmodel.Code, limit int, wait time.Duration) error {
	return errmodel.E(code, errmodel.WithDetails(errmodel.SignInLimit{Limit: limit, RetryAfterSeconds: max(1, int64(wait.Seconds()+0.5))}))
}

// accountsLimit is the accounts-per-device limit for d's kind (0: off).
func (s *Engine) accountsLimit(d authflow.SignInDevice) int {
	switch {
	case d.ID == "":
		return 0
	case d.ByAddress():
		return max(0, s.cfg.SignIn.AccountsPerAddress)
	}
	return max(0, s.cfg.SignIn.AccountsPerDevice)
}

// admitNewAccount refuses to create an account from a device that already
// has its limit of accounts, before the account exists.
func (s *Engine) admitNewAccount(ctx context.Context) error {
	d := authflow.SignInDeviceFrom(ctx)
	limit := s.accountsLimit(d)
	if limit == 0 {
		return nil
	}
	var accounts deviceAccounts
	if _, err := s.ephemGetJSON(ctx, keySignInDevice+digest(d.ID), &accounts); err != nil {
		return err
	}
	now := time.Now().Unix()
	if oldest, n := liveAccounts(accounts, now); n >= limit {
		return signInLimit(errmodel.CodeTooManyAccounts, limit, time.Duration(oldest+int64(signInWindow.Seconds())-now)*time.Second)
	}
	return nil
}

// liveAccounts counts the accounts signed in within the window and the
// oldest of their latest sign-ins.
func liveAccounts(accounts deviceAccounts, now int64) (oldest int64, n int) {
	for _, at := range accounts {
		if at > now-int64(signInWindow.Seconds()) {
			if n == 0 || at < oldest {
				oldest = at
			}
			n++
		}
	}
	return oldest, n
}

// admitAccountOnDevice counts userID on d, refusing a new account past the
// device's limit. A cookieless sign-in also starts the cookie it is issued
// with on this account.
func (s *Engine) admitAccountOnDevice(ctx context.Context, userID string, d authflow.SignInDevice) error {
	limit := s.accountsLimit(d)
	if limit == 0 {
		return nil
	}
	now := time.Now().Unix()
	var refused error
	if err := updateEphemeralJSON(ctx, s, keySignInDevice+digest(d.ID), signInWindow, func(accounts *deviceAccounts) bool {
		refused = nil
		member := digest(d.ID, userID)
		_, counted := (*accounts)[member]
		oldest, n := liveAccounts(*accounts, now)
		if !counted && n >= limit {
			refused = signInLimit(errmodel.CodeTooManyAccounts, limit, time.Duration(oldest+int64(signInWindow.Seconds())-now)*time.Second)
			return false
		}
		*accounts = pruneAccounts(*accounts, now)
		(*accounts)[member] = now
		return true
	}); err != nil {
		return err
	}
	if refused != nil || d.Issued == "" || s.cfg.SignIn.AccountsPerDevice <= 0 {
		return refused
	}
	return updateEphemeralJSON(ctx, s, keySignInDevice+digest(d.Issued), signInWindow, func(accounts *deviceAccounts) bool {
		*accounts = pruneAccounts(*accounts, now)
		(*accounts)[digest(d.Issued, userID)] = now
		return true
	})
}

func pruneAccounts(accounts deviceAccounts, now int64) deviceAccounts {
	out := deviceAccounts{}
	for k, at := range accounts {
		if at > now-int64(signInWindow.Seconds()) {
			out[k] = at
		}
	}
	return out
}

// admitDeviceOnAccount records d on the account unless it is new past the
// account's limit and the sign-in proved nothing the owner holds: then
// needsCode is set, and refused is the error when no code can be sent.
func (s *Engine) admitDeviceOnAccount(ctx context.Context, userID string, d authflow.SignInDevice, provesOwner bool) (needsCode bool, refused error, err error) {
	limit := s.cfg.SignIn.NewDevicesPerAccount
	if limit <= 0 || d.ID == "" {
		return false, nil, nil
	}
	now := time.Now().Unix()
	err = updateEphemeralJSON(ctx, s, keySignInAccount+userID, knownDeviceWindow, func(devices *accountDevices) bool {
		needsCode, refused = false, nil
		*devices = pruneDevices(*devices, now)
		member := digest(userID, d.ID)
		seen, known := (*devices)[member]
		if !known {
			var oldest int64
			n := 0
			for _, e := range *devices {
				if e.New > now-int64(signInWindow.Seconds()) {
					if n == 0 || e.New < oldest {
						oldest = e.New
					}
					n++
				}
			}
			if n >= limit && !provesOwner {
				needsCode = true
				refused = signInLimit(errmodel.CodeTooManyDevices, limit, time.Duration(oldest+int64(signInWindow.Seconds())-now)*time.Second)
				return false
			}
			seen.New = now
		}
		seen.Seen = now
		(*devices)[member] = seen
		if d.Issued != "" {
			issued := (*devices)[digest(userID, d.Issued)]
			issued.Seen = now
			(*devices)[digest(userID, d.Issued)] = issued
		}
		return true
	})
	return needsCode, refused, err
}

// pruneDevices drops devices unseen for knownDeviceWindow, then the least
// recently seen beyond maxKnownDevices.
func pruneDevices(devices accountDevices, now int64) accountDevices {
	type entry struct {
		key string
		accountDevice
	}
	var live []entry
	for k, e := range devices {
		if e.Seen > now-int64(knownDeviceWindow.Seconds()) {
			live = append(live, entry{k, e})
		}
	}
	slices.SortFunc(live, func(a, b entry) int { return int(b.Seen - a.Seen) })
	out := accountDevices{}
	for _, e := range live[:min(len(live), maxKnownDevices)] {
		out[e.key] = e.accountDevice
	}
	return out
}

// admitSignIn runs both limits for a first factor on userID. A sign-in that
// proved the owner's email or phone or a second factor, or will be asked for
// a second factor next, needs no device code.
func (s *Engine) admitSignIn(ctx context.Context, userID string, in loginSessionInput, secondFactorNext bool) (needsCode bool, refused error, err error) {
	if err := s.admitAccountOnDevice(ctx, userID, in.Device); err != nil {
		return false, nil, err
	}
	provesOwner := secondFactorNext || hasAuthMethod(in.AuthMethods, "mfa") || hasAuthMethod(in.AuthMethods, "email") || hasAuthMethod(in.AuthMethods, "sms")
	return s.admitDeviceOnAccount(ctx, userID, in.Device, provesOwner)
}

// deviceCodeChannels are the account's proven channels that can deliver a
// code now, email first: the owner hears of the new device there.
func (s *Engine) deviceCodeChannels(u *db.User) []string {
	var out []string
	if _, ok := provenAddress(u, passwordlessChannelEmail); ok && s.EmailAvailable() {
		out = append(out, passwordlessChannelEmail)
	}
	if _, ok := provenAddress(u, passwordlessChannelSMS); ok && s.SMSAvailable() {
		out = append(out, passwordlessChannelSMS)
	}
	return out
}

func deviceCodeKey(userID, nonceHash string) string {
	return keyDeviceCode + userID + ":" + nonceHash
}

// challengeNewDevice parks the sign-in on a code sent to the owner, as the
// account's one current first-factor proof (like a second-factor challenge).
func (s *Engine) challengeNewDevice(ctx context.Context, user *db.User, proof loginProof, refused error) (authflow.LoginOutcome, error) {
	channels := s.deviceCodeChannels(user)
	if len(channels) == 0 {
		return authflow.LoginOutcome{}, refused
	}
	nonce := secret.Token(32)
	proof.NonceHash, proof.Issuer, proof.Enrollment, proof.DeviceCode = secret.Hash(nonce), s.cfg.Token.Issuer, false, true
	if proof.AuthenticatedAt.IsZero() {
		proof.AuthenticatedAt = time.Now().UTC()
	}
	if err := s.ephemSetJSON(ctx, keyTwoFactorChallenge+user.ID, proof, 10*time.Minute); err != nil {
		return authflow.LoginOutcome{}, err
	}
	to, err := s.sendDeviceCode(ctx, user, proof.NonceHash, channels[0])
	if err != nil {
		return authflow.LoginOutcome{}, err
	}
	return authflow.LoginOutcome{
		Kind: authflow.LoginDeviceVerificationRequired, UserID: user.ID, ReturnTo: proof.ReturnTo, Created: proof.Created,
		Device: &authflow.DeviceChallenge{Challenge: nonce, Channel: channels[0], Destination: to, Channels: channels},
	}, nil
}

// sendDeviceCode sends a fresh code for the proof to the account's proven
// address on channel, replacing any earlier one.
func (s *Engine) sendDeviceCode(ctx context.Context, u *db.User, nonceHash, channel string) (string, error) {
	to, ok := provenAddress(u, channel)
	if !ok {
		return "", errmodel.E(errmodel.CodeContactNotVerified)
	}
	if n, err := s.ephemIncr(ctx, keyDeviceCodeSent+u.ID, time.Hour); err != nil {
		return "", err
	} else if n > maxDeviceCodesPerHour {
		return "", signInLimit(errmodel.CodeTooManyDevices, s.cfg.SignIn.NewDevicesPerAccount, time.Hour)
	}
	code := secret.Digits(6)
	if err := s.storeTwoFactorCode(ctx, deviceCodeKey(u.ID, nonceHash), twoFactorData{CodeHash: secret.Hash(code), Method: channel, Destination: to}); err != nil {
		return "", err
	}
	language := s.messageLanguage(ctx, deref(u.PreferredLanguage))
	if channel == passwordlessChannelSMS {
		return to, s.sendSMS(ctx, iam.SMSMessage{Kind: iam.MessageNewDeviceCode, To: to, Language: language, Code: code})
	}
	return to, s.sendEmail(ctx, iam.EmailMessage{Kind: iam.MessageNewDeviceCode, To: to, Username: deref(u.Username), Language: language, Code: code})
}

// loadDeviceProof is the account's current proof while it waits on a device
// code.
func (s *Engine) loadDeviceProof(ctx context.Context, userID, challenge string) (loginProof, error) {
	proof, err := s.loadLoginProof(ctx, userID, challenge)
	if err != nil || !proof.DeviceCode {
		return loginProof{}, jwt.ErrTokenUnverifiable
	}
	return proof, nil
}

// SendDeviceVerification sends the waiting sign-in a new code, on channel
// ("email" or "sms"; empty: the first available).
func (s *Engine) SendDeviceVerification(ctx context.Context, userID, challenge, channel string) (*authflow.DeviceChallenge, error) {
	proof, err := s.loadDeviceProof(ctx, userID, challenge)
	if err != nil {
		return nil, err
	}
	u, err := s.getUserByID(ctx, userID)
	if err != nil {
		return nil, err
	}
	channels := s.deviceCodeChannels(u)
	if channel = strings.TrimSpace(channel); channel == "" && len(channels) > 0 {
		channel = channels[0]
	}
	if !slices.Contains(channels, channel) {
		return nil, errmodel.E(errmodel.CodeContactNotVerified)
	}
	to, err := s.sendDeviceCode(ctx, u, proof.NonceHash, channel)
	if err != nil {
		return nil, err
	}
	return &authflow.DeviceChallenge{Challenge: challenge, Channel: channel, Destination: to, Channels: channels}, nil
}

// ConfirmDeviceVerification checks the device code, makes the device known
// to the account and continues the sign-in: a session, or its second factor.
// ErrInvalidCode is a wrong code; ErrCodeExpired, no live one.
func (s *Engine) ConfirmDeviceVerification(ctx context.Context, in authflow.DeviceVerificationInput) (authflow.LoginOutcome, error) {
	proof, err := s.loadDeviceProof(ctx, in.UserID, in.Challenge)
	if err != nil {
		return authflow.LoginOutcome{}, err
	}
	if err := s.chargeLoginProofAttempt(ctx, proof); err != nil {
		return authflow.LoginOutcome{}, err
	}
	key := deviceCodeKey(in.UserID, proof.NonceHash)
	var sent twoFactorData
	if _, ok, err := s.ephemReadJSON(ctx, key, &sent); err != nil {
		return authflow.LoginOutcome{}, err
	} else if !ok {
		return authflow.LoginOutcome{}, errmodel.ErrCodeExpired
	}
	valid, err := s.consumeTwoFactorCode(ctx, key, secret.Hash(strings.TrimSpace(in.Code)), sent.Method)
	if err != nil {
		return authflow.LoginOutcome{}, err
	}
	if !valid {
		return authflow.LoginOutcome{}, errmodel.ErrInvalidCode
	}
	u, err := s.getUserByID(ctx, in.UserID)
	if err != nil {
		return authflow.LoginOutcome{}, err
	}
	if to, ok := provenAddress(u, sent.Method); !ok || to != sent.Destination {
		return authflow.LoginOutcome{}, errmodel.ErrCodeExpired
	}
	if _, _, err := s.admitDeviceOnAccount(ctx, in.UserID, proof.Input.Device, true); err != nil {
		return authflow.LoginOutcome{}, err
	}
	proof.Input.UserAgent, proof.Input.IP = in.UserAgent, in.IP
	return s.finishFirstFactor(ctx, proof)
}
