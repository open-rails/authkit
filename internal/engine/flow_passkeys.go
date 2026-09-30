package engine

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net"
	"strings"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
	jwt "github.com/golang-jwt/jwt/v5"
	"github.com/jackc/pgx/v5"

	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/internal/authflow"
	"github.com/open-rails/authkit/internal/db"
	"github.com/open-rails/authkit/internal/errmodel"
)

const passkeyCeremonyTTL = 10 * time.Minute

// Ceremony purposes: a finish only consumes a ceremony begun for the same purpose,
// so a verification challenge can never be turned into a session mint and an
// account-bootstrap challenge can never attach a credential to an existing user.
const (
	passkeyPurposeRegister = "register"
	passkeyPurposeLogin    = "login"
	passkeyPurposeStepUp   = "step_up"
)

// PasskeysEnabled reports whether passkey (WebAuthn) support is configured.
// Passkeys require a Relying Party ID (PasskeyConfig.RPID); without it every
// WebAuthn ceremony fails closed (the origin must match the RPID). The HTTP
// transport uses this to skip mounting the /passkeys/* routes entirely rather
// than exposing endpoints that can only error.
func (s *Engine) PasskeysEnabled() bool { return strings.TrimSpace(s.cfg.Passkeys.RPID) != "" }

// VerifiedPasskey is the identity proof a discoverable assertion yields: the
// stable user and the credential that signed. It carries no session, token,
// cookie or claim; the host binds it to its own pending operation.
type verifiedPasskey struct {
	credentialVersion int64
	UserID            string
	PasskeyID         string
	CredentialID      string
	BackupEligible    bool
	BackupState       bool
}

type passkeyUser struct {
	credentialVersion int64
	id                string
	handle            []byte
	name              string
	displayName       string
	credentials       []webauthn.Credential
}

func (u passkeyUser) WebAuthnID() []byte                         { return u.handle }
func (u passkeyUser) WebAuthnName() string                       { return u.name }
func (u passkeyUser) WebAuthnDisplayName() string                { return u.displayName }
func (u passkeyUser) WebAuthnCredentials() []webauthn.Credential { return u.credentials }

func (s *Engine) passkeyUserVerification() protocol.UserVerificationRequirement {
	return protocol.UserVerificationRequirement(s.cfg.Passkeys.UserVerification)
}

func (s *Engine) webAuthn() (*webauthn.WebAuthn, error) {
	return webauthn.New(&webauthn.Config{
		RPID:                  s.cfg.Passkeys.RPID,
		RPDisplayName:         s.cfg.Passkeys.RPDisplayName,
		RPOrigins:             append([]string(nil), s.cfg.Passkeys.Origins...),
		AttestationPreference: protocol.PreferNoAttestation,
		AuthenticatorSelection: protocol.AuthenticatorSelection{
			UserVerification: s.passkeyUserVerification(),
		},
		// No extension is requested and no output is read, so a client that
		// volunteers one must not fail the ceremony.
		ExtensionsUnsolicitedOutputPolicy: protocol.UnsolicitedOutputPolicyIgnore,
	})
}

// BeginPasskeyRegistration starts adding a passkey to an already identified
// user. The same ceremony finishes as either FinishPasskeyRegistration (add)
// or FinishPasskeyReplacement (replace all).
func (s *Engine) BeginPasskeyRegistration(ctx context.Context, userID string) (*protocol.CredentialCreation, error) {
	if err := s.RequireProvenContact(ctx, strings.TrimSpace(userID)); err != nil {
		return nil, err
	}
	u, err := s.passkeyUser(ctx, strings.TrimSpace(userID), true)
	if err != nil {
		return nil, err
	}
	return s.beginPasskeyCreation(ctx, u, passkeyPurposeRegister, s.passkeyUserVerification())
}

func (s *Engine) beginPasskeyCreation(ctx context.Context, u passkeyUser, purpose string, uv protocol.UserVerificationRequirement) (*protocol.CredentialCreation, error) {
	wa, err := s.webAuthn()
	if err != nil {
		return nil, err
	}
	required := true
	creation, session, err := wa.BeginRegistration(u,
		webauthn.WithResidentKeyRequirement(protocol.ResidentKeyRequirementRequired),
		webauthn.WithAuthenticatorSelection(protocol.AuthenticatorSelection{
			RequireResidentKey: &required,
			ResidentKey:        protocol.ResidentKeyRequirementRequired,
			UserVerification:   uv,
		}),
		webauthn.WithExclusions(webauthn.Credentials(u.credentials).CredentialDescriptors()),
		webauthn.WithConveyancePreference(protocol.PreferNoAttestation),
	)
	if err != nil {
		return nil, err
	}
	return creation, s.storePasskeySession(ctx, session, purpose, u.id, "")
}

func (s *Engine) FinishPasskeyRegistration(ctx context.Context, userID string, response []byte) (iam.Passkey, error) {
	if err := s.RequireProvenContact(ctx, strings.TrimSpace(userID)); err != nil {
		return iam.Passkey{}, err
	}
	cred, err := s.finishPasskeyCreation(ctx, userID, response)
	if err != nil {
		return iam.Passkey{}, err
	}
	return s.insertPasskey(ctx, strings.TrimSpace(userID), cred, nil)
}

func (s *Engine) finishPasskeyCreation(ctx context.Context, userID string, response []byte) (*webauthn.Credential, error) {
	userID = strings.TrimSpace(userID)
	parsed, err := protocol.ParseCredentialCreationResponseBytes(response)
	if err != nil {
		return nil, err
	}
	data, session, err := s.consumePasskeySession(ctx, parsed.Response.CollectedClientData.Challenge)
	if err != nil {
		return nil, err
	}
	if data.Purpose != passkeyPurposeRegister || userID == "" || data.UserID != userID {
		return nil, errmodel.ErrPasskeyNotFound
	}
	u, err := s.passkeyUser(ctx, userID, true)
	if err != nil {
		return nil, err
	}
	return s.createCredential(u, session, parsed)
}

func (s *Engine) createCredential(u passkeyUser, session webauthn.SessionData, parsed *protocol.ParsedCredentialCreationData) (*webauthn.Credential, error) {
	wa, err := s.webAuthn()
	if err != nil {
		return nil, err
	}
	cred, err := wa.CreateCredential(u, session, parsed)
	if err != nil {
		return nil, err
	}
	if !cred.Flags.UserVerified {
		return nil, errmodel.ErrPasskeyUserVerificationRequired
	}
	return cred, nil
}

// BeginPasskeyLogin always issues a discoverable assertion with an empty
// allowCredentials list (AK2-PK-002): scoping it to a known identifier would
// leak account existence and credential ids to an unauthenticated caller.
// The asserted credential's user handle resolves the user at finish.
func (s *Engine) BeginPasskeyLogin(ctx context.Context) (*protocol.CredentialAssertion, error) {
	return s.beginDiscoverableAssertion(ctx, passkeyPurposeLogin, s.passkeyUserVerification())
}

// FinishPasskeyLogin composes the verification primitive with the browser
// session issuance; it is the only passkey path that mints a session.
func (s *Engine) FinishPasskeyLogin(ctx context.Context, response []byte, userAgent string, ip net.IP) (authflow.LoginOutcome, error) {
	verified, err := s.finishDiscoverableAssertion(ctx, passkeyPurposeLogin, response)
	if err != nil {
		return authflow.LoginOutcome{}, err
	}
	address := ""
	if ip != nil {
		address = ip.String()
	}
	return s.finishFirstFactor(ctx, loginProof{Version: verified.credentialVersion, PasskeyID: verified.PasskeyID, AuthenticatedAt: time.Now().UTC(), Input: loginSessionInput{UserID: verified.UserID, UserAgent: userAgent, IP: address, Event: "passkey_login", AuthMethods: []string{"swk", "mfa"}}})
}

func (s *Engine) beginDiscoverableAssertion(ctx context.Context, purpose string, uv protocol.UserVerificationRequirement) (*protocol.CredentialAssertion, error) {
	wa, err := s.webAuthn()
	if err != nil {
		return nil, err
	}
	assertion, session, err := wa.BeginDiscoverableLogin(webauthn.WithUserVerification(uv))
	if err != nil {
		return nil, err
	}
	return assertion, s.storePasskeySession(ctx, session, purpose, "", "")
}

func (s *Engine) finishDiscoverableAssertion(ctx context.Context, purpose string, response []byte) (verifiedPasskey, error) {
	parsed, err := protocol.ParseCredentialRequestResponseBytes(response)
	if err != nil {
		return verifiedPasskey{}, err
	}
	data, session, err := s.consumePasskeySession(ctx, parsed.Response.CollectedClientData.Challenge)
	if err != nil {
		return verifiedPasskey{}, err
	}
	if data.Purpose != purpose {
		return verifiedPasskey{}, jwt.ErrTokenUnverifiable
	}
	wa, err := s.webAuthn()
	if err != nil {
		return verifiedPasskey{}, err
	}
	webUser, cred, err := wa.ValidatePasskeyLogin(func(_, userHandle []byte) (webauthn.User, error) {
		return s.passkeyUserByHandle(ctx, userHandle, purpose == passkeyPurposeLogin)
	}, session, parsed)
	if err != nil {
		return verifiedPasskey{}, err
	}
	user := webUser.(passkeyUser)
	id, err := s.acceptAssertion(ctx, user.id, parsed, cred)
	if err != nil {
		return verifiedPasskey{}, err
	}
	return verifiedPasskey{
		credentialVersion: user.credentialVersion,
		UserID:            user.id,
		PasskeyID:         id,
		CredentialID:      base64.RawURLEncoding.EncodeToString(cred.ID),
		BackupEligible:    cred.Flags.BackupEligible,
		BackupState:       cred.Flags.BackupState,
	}, nil
}

// acceptAssertion finishes a validated assertion by userID's cred: the
// ceremony verified the user, the credential shows no clone, and its use is
// recorded. It returns the passkey's id.
func (s *Engine) acceptAssertion(ctx context.Context, userID string, parsed *protocol.ParsedCredentialAssertionData, cred *webauthn.Credential) (string, error) {
	// cred.Flags.UserVerified is the latched uvInitialized record, not this
	// assertion's flag; the requirement is per ceremony.
	if !parsed.Response.AuthenticatorData.Flags.UserVerified() {
		return "", errmodel.ErrPasskeyUserVerificationRequired
	}
	if cred.Authenticator.CloneWarning && cred.Authenticator.SignCount > 0 {
		return "", errmodel.ErrPasskeyCloneDetected
	}
	return s.updatePasskeyAfterUse(ctx, userID, cred)
}

func (s *Engine) ListPasskeys(ctx context.Context, userID string) ([]iam.Passkey, error) {
	rows, err := s.q.PasskeysByUser(ctx, db.PasskeysByUserParams{UserID: userID, Rpid: s.cfg.Passkeys.RPID})
	if err != nil {
		return nil, err
	}
	var out []iam.Passkey
	for _, p := range rows {
		out = append(out, publicPasskey(p))
	}
	return out, nil
}

// RenamePasskey sets the label of the account's live passkey id (empty clears
// it); ErrPasskeyNotFound when the account holds no such passkey.
func (s *Engine) RenamePasskey(ctx context.Context, userID, id, label string) error {
	if !isUUID(strings.TrimSpace(id)) {
		return errmodel.ErrPasskeyNotFound
	}
	n, err := s.q.PasskeyRename(ctx, db.PasskeyRenameParams{Label: nullable(strings.TrimSpace(label)), ID: strings.TrimSpace(id), UserID: strings.TrimSpace(userID)})
	if err != nil {
		return err
	}
	if n == 0 {
		return errmodel.ErrPasskeyNotFound
	}
	return nil
}

// DeletePasskey deletes the account's passkey id; a deleted one stays
// deleted, and ErrPasskeyNotFound when the account never held it.
func (s *Engine) DeletePasskey(ctx context.Context, userID, id string) error {
	if !isUUID(strings.TrimSpace(id)) {
		return errmodel.ErrPasskeyNotFound
	}
	n, err := s.q.PasskeyDelete(ctx, db.PasskeyDeleteParams{ID: strings.TrimSpace(id), UserID: strings.TrimSpace(userID)})
	if err != nil {
		return err
	}
	if n == 0 {
		return errmodel.ErrPasskeyNotFound
	}
	return nil
}

// storePasskeySession stores a ceremony begun for purpose, by userID and, for
// a step-up, the session it re-authenticates.
func (s *Engine) storePasskeySession(ctx context.Context, session *webauthn.SessionData, purpose, userID, sessionID string) error {
	b, err := json.Marshal(session)
	if err != nil {
		return err
	}
	return s.storePasskeyCeremony(ctx, session.Challenge, passkeyCeremonyData{Purpose: purpose, UserID: strings.TrimSpace(userID), SessionID: sessionID, Session: b}, passkeyCeremonyTTL)
}

func (s *Engine) consumePasskeySession(ctx context.Context, challenge string) (passkeyCeremonyData, webauthn.SessionData, error) {
	data, err := s.consumePasskeyCeremony(ctx, challenge)
	if err != nil {
		return data, webauthn.SessionData{}, err
	}
	var session webauthn.SessionData
	if err := json.Unmarshal(data.Session, &session); err != nil {
		return data, session, err
	}
	return data, session, nil
}

func (s *Engine) passkeyUser(ctx context.Context, userID string, createHandle bool) (passkeyUser, error) {
	return s.passkeyUserForProof(ctx, userID, createHandle, false)
}

func (s *Engine) passkeyUserForProof(ctx context.Context, userID string, createHandle, allowRecovery bool) (passkeyUser, error) {
	u, err := s.getUserByID(ctx, userID)
	if err != nil || u == nil {
		return passkeyUser{}, errOrUnauthorized(err)
	}
	checkAccess := s.ensureUserAccess
	if allowRecovery {
		checkAccess = s.ensureLoginProofAccess
	}
	if err := checkAccess(ctx, u); err != nil {
		return passkeyUser{}, err
	}
	handle, err := s.passkeyHandle(ctx, userID, createHandle)
	if err != nil {
		return passkeyUser{}, err
	}
	creds, err := s.passkeyCredentialsByUser(ctx, userID)
	if err != nil {
		return passkeyUser{}, err
	}
	name := userID
	if u.Email != nil && *u.Email != "" {
		name = *u.Email
	} else if u.Username != nil && *u.Username != "" {
		name = *u.Username
	}
	return passkeyUser{id: userID, handle: handle, name: name, displayName: name, credentials: creds}, nil
}

func (s *Engine) passkeyUserByHandle(ctx context.Context, handle []byte, allowRecovery bool) (passkeyUser, error) {
	userID, err := s.q.PasskeyHandleUser(ctx, handle)
	if err != nil {
		return passkeyUser{}, err
	}
	version, err := s.q.UserCredentialVersion(ctx, userID)
	if err != nil {
		return passkeyUser{}, err
	}
	user, err := s.passkeyUserForProof(ctx, userID, false, allowRecovery)
	user.credentialVersion = version.CredentialVersion
	return user, err
}

func (s *Engine) passkeyHandle(ctx context.Context, userID string, create bool) ([]byte, error) {
	handle, err := s.q.PasskeyHandleByUser(ctx, userID)
	if err == nil {
		return handle, nil
	}
	if !errors.Is(err, pgx.ErrNoRows) || !create {
		return nil, err
	}
	handle = make([]byte, 64)
	if _, err := rand.Read(handle); err != nil {
		return nil, err
	}
	return s.q.PasskeyHandleUpsert(ctx, db.PasskeyHandleUpsertParams{UserID: userID, UserHandle: handle})
}

func (s *Engine) passkeyCredentialsByUser(ctx context.Context, userID string) ([]webauthn.Credential, error) {
	rows, err := s.q.PasskeysByUser(ctx, db.PasskeysByUserParams{UserID: userID, Rpid: s.cfg.Passkeys.RPID})
	if err != nil {
		return nil, err
	}
	var out []webauthn.Credential
	for _, p := range rows {
		out = append(out, webAuthnCredential(p))
	}
	return out, nil
}

// passkeyFlags decodes the persisted authenticator flags byte (#235).
func passkeyFlags(p db.UserPasskey) webauthn.CredentialFlags {
	if len(p.Flags) == 0 {
		return webauthn.CredentialFlags{}
	}
	return webauthn.NewCredentialFlags(protocol.AuthenticatorFlags(p.Flags[0]))
}

// publicPasskey is the one mapping from a passkey row to what callers see.
func publicPasskey(p db.UserPasskey) iam.Passkey {
	flags := passkeyFlags(p)
	out := iam.Passkey{
		ID: p.ID, Label: p.Label, Transports: p.Transports,
		BackupEligible: flags.BackupEligible, BackupState: flags.BackupState, CreatedAt: p.CreatedAt, LastUsedAt: p.LastUsedAt,
	}
	if p.AuthenticatorAttachment != "" {
		out.AuthenticatorAttachment = &p.AuthenticatorAttachment
	}
	return out
}

// webAuthnCredential is the one mapping from a passkey row to the credential a
// WebAuthn ceremony verifies against.
func webAuthnCredential(p db.UserPasskey) webauthn.Credential {
	var transport []protocol.AuthenticatorTransport
	for _, t := range p.Transports {
		transport = append(transport, protocol.AuthenticatorTransport(t))
	}
	return webauthn.Credential{
		ID:                p.CredentialID,
		PublicKey:         p.PublicKey,
		AttestationType:   p.AttestationType,
		AttestationFormat: p.AttestationFmt,
		Transport:         transport,
		Flags:             passkeyFlags(p),
		Authenticator: webauthn.Authenticator{
			AAGUID:       p.Aaguid,
			SignCount:    uint32(p.SignCount),
			CloneWarning: p.CloneWarning,
			Attachment:   protocol.AuthenticatorAttachment(p.AuthenticatorAttachment),
		},
	}
}

func (s *Engine) insertPasskey(ctx context.Context, userID string, cred *webauthn.Credential, label *string) (iam.Passkey, error) {
	p, err := s.q.PasskeyInsert(ctx, db.PasskeyInsertParams{
		UserID: userID, Rpid: s.cfg.Passkeys.RPID, CredentialID: cred.ID, PublicKey: cred.PublicKey,
		SignCount: int64(cred.Authenticator.SignCount), CloneWarning: cred.Authenticator.CloneWarning, Aaguid: nullBytes(cred.Authenticator.AAGUID),
		Transports: transportStrings(cred.Transport), AuthenticatorAttachment: string(cred.Authenticator.Attachment),
		Flags: []byte{byte(cred.Flags.ProtocolValue())}, AttestationType: cred.AttestationType, AttestationFmt: cred.AttestationFormat, Label: label,
	})
	if err != nil {
		return iam.Passkey{}, err
	}
	return publicPasskey(p), nil
}

func (s *Engine) updatePasskeyAfterUse(ctx context.Context, userID string, cred *webauthn.Credential) (string, error) {
	id, err := s.q.PasskeyRecordUse(ctx, db.PasskeyRecordUseParams{
		SignCount: int64(cred.Authenticator.SignCount), CloneWarning: cred.Authenticator.CloneWarning, Flags: []byte{byte(cred.Flags.ProtocolValue())},
		UserID: userID, Rpid: s.cfg.Passkeys.RPID, CredentialID: cred.ID,
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return "", errmodel.ErrPasskeyNotFound
	}
	return id, err
}

func transportStrings(in []protocol.AuthenticatorTransport) []string {
	out := make([]string, 0, len(in))
	for _, v := range in {
		out = append(out, string(v))
	}
	return out
}

func nullBytes(in []byte) []byte {
	if len(in) == 0 {
		return nil
	}
	return in
}
