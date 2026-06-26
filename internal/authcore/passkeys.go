package authcore

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	authkit "github.com/open-rails/authkit"
	"net"
	"net/url"
	"strings"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/jackc/pgx/v5"

	"github.com/open-rails/authkit/internal/db"
)

const passkeyCeremonyTTL = 10 * time.Minute

var (
	ErrPasskeyNotFound                 = authkit.ErrPasskeyNotFound
	ErrPasskeyUserVerificationRequired = authkit.ErrPasskeyUserVerificationRequired
	ErrPasskeyCloneDetected            = authkit.ErrPasskeyCloneDetected
)

type Passkey struct {
	ID                      string     `json:"id"`
	UserID                  string     `json:"user_id,omitempty"`
	Label                   *string    `json:"label,omitempty"`
	Transports              []string   `json:"transports,omitempty"`
	AuthenticatorAttachment string     `json:"authenticator_attachment,omitempty"`
	BackupEligible          bool       `json:"backup_eligible"`
	BackupState             bool       `json:"backup_state"`
	CreatedAt               time.Time  `json:"created_at"`
	LastUsedAt              *time.Time `json:"last_used_at,omitempty"`
}

type PasskeyLoginResult struct {
	UserID       string
	SessionID    string
	RefreshToken string
	AccessToken  string
	ExpiresAt    time.Time
}

type passkeyUser struct {
	id          string
	handle      []byte
	name        string
	displayName string
	credentials []webauthn.Credential
}

func (u passkeyUser) WebAuthnID() []byte                         { return u.handle }
func (u passkeyUser) WebAuthnName() string                       { return u.name }
func (u passkeyUser) WebAuthnDisplayName() string                { return u.displayName }
func (u passkeyUser) WebAuthnCredentials() []webauthn.Credential { return u.credentials }

func normalizePasskeyConfig(cfg PasskeyConfig, baseURL, issuer string) (string, string, []string, string, error) {
	origin := strings.TrimRight(strings.TrimSpace(baseURL), "/")
	u, err := url.Parse(origin)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return "", "", nil, "", errors.New("authkit: Passkeys require a valid BaseURL origin")
	}
	u.Path, u.RawQuery, u.Fragment = "", "", ""
	origin = u.String()

	rpid := strings.ToLower(strings.TrimSpace(cfg.RPID))
	if rpid == "" {
		rpid = strings.ToLower(u.Hostname())
	}
	name := strings.TrimSpace(cfg.RPDisplayName)
	if name == "" {
		name = strings.TrimSpace(issuer)
	}
	if name == "" {
		name = rpid
	}
	origins := append([]string(nil), cfg.Origins...)
	if len(origins) == 0 {
		origins = []string{origin}
	}
	for i, raw := range origins {
		o, err := url.Parse(strings.TrimRight(strings.TrimSpace(raw), "/"))
		if err != nil || o.Scheme == "" || o.Host == "" {
			return "", "", nil, "", errors.New("authkit: invalid Passkey origin")
		}
		host := strings.ToLower(o.Hostname())
		if host != rpid && !strings.HasSuffix(host, "."+rpid) {
			return "", "", nil, "", errors.New("authkit: Passkey origin host must match RPID or a subdomain")
		}
		o.Path, o.RawQuery, o.Fragment = "", "", ""
		origins[i] = o.String()
	}
	return rpid, name, origins, normalizePasskeyUserVerification(cfg.UserVerification), nil
}

func normalizePasskeyUserVerification(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "required":
		return string(protocol.VerificationRequired)
	case "discouraged":
		return string(protocol.VerificationDiscouraged)
	default:
		return string(protocol.VerificationPreferred)
	}
}

func (s *Service) passkeyUserVerification() protocol.UserVerificationRequirement {
	switch normalizePasskeyUserVerification(s.opts.PasskeyUserVerification) {
	case string(protocol.VerificationRequired):
		return protocol.VerificationRequired
	case string(protocol.VerificationDiscouraged):
		return protocol.VerificationDiscouraged
	default:
		return protocol.VerificationPreferred
	}
}

func (s *Service) webAuthn() (*webauthn.WebAuthn, error) {
	return webauthn.New(&webauthn.Config{
		RPID:                  s.opts.PasskeyRPID,
		RPDisplayName:         s.opts.PasskeyRPDisplayName,
		RPOrigins:             append([]string(nil), s.opts.PasskeyOrigins...),
		AttestationPreference: protocol.PreferNoAttestation,
		AuthenticatorSelection: protocol.AuthenticatorSelection{
			UserVerification: s.passkeyUserVerification(),
		},
	})
}

func (s *Service) BeginPasskeyRegistration(ctx context.Context, userID string) (*protocol.CredentialCreation, error) {
	u, err := s.passkeyUser(ctx, strings.TrimSpace(userID), true)
	if err != nil {
		return nil, err
	}
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
			UserVerification:   s.passkeyUserVerification(),
		}),
		webauthn.WithExclusions(webauthn.Credentials(u.credentials).CredentialDescriptors()),
		webauthn.WithConveyancePreference(protocol.PreferNoAttestation),
	)
	if err != nil {
		return nil, err
	}
	return creation, s.storePasskeySession(ctx, session, userID)
}

func (s *Service) FinishPasskeyRegistration(ctx context.Context, userID string, response []byte) (Passkey, error) {
	parsed, err := protocol.ParseCredentialCreationResponseBytes(response)
	if err != nil {
		return Passkey{}, err
	}
	data, session, err := s.consumePasskeySession(ctx, parsed.Response.CollectedClientData.Challenge)
	if err != nil {
		return Passkey{}, err
	}
	if data.UserID != strings.TrimSpace(userID) {
		return Passkey{}, ErrPasskeyNotFound
	}
	u, err := s.passkeyUser(ctx, userID, true)
	if err != nil {
		return Passkey{}, err
	}
	wa, err := s.webAuthn()
	if err != nil {
		return Passkey{}, err
	}
	cred, err := wa.CreateCredential(u, session, parsed)
	if err != nil {
		return Passkey{}, err
	}
	if !cred.Flags.UserVerified {
		return Passkey{}, ErrPasskeyUserVerificationRequired
	}
	return s.createPasskey(ctx, userID, cred, nil)
}

func (s *Service) BeginPasskeyLogin(ctx context.Context, identifier string) (*protocol.CredentialAssertion, error) {
	// AK2-PK-002: `identifier` is accepted for API compatibility but intentionally
	// NOT used to scope the assertion. Branching to wa.BeginLogin for a known user
	// would populate allowCredentials with that user's credential descriptors,
	// leaking to an UNAUTHENTICATED caller both whether the account exists and its
	// credential IDs (an enumeration oracle: the response shape differs for known
	// vs unknown identifiers). Always issue a discoverable (usernameless) assertion
	// with an empty allowCredentials list so the response is identical regardless
	// of input. Passkeys are discoverable/resident, so the authenticator selects
	// the credential and FinishPasskeyLogin resolves the user from the asserted
	// credential's user handle.
	_ = identifier
	wa, err := s.webAuthn()
	if err != nil {
		return nil, err
	}
	assertion, session, err := wa.BeginDiscoverableLogin(webauthn.WithUserVerification(s.passkeyUserVerification()))
	if err != nil {
		return nil, err
	}
	return assertion, s.storePasskeySession(ctx, session, "")
}

func (s *Service) FinishPasskeyLogin(ctx context.Context, response []byte, userAgent string, ip net.IP) (PasskeyLoginResult, error) {
	parsed, err := protocol.ParseCredentialRequestResponseBytes(response)
	if err != nil {
		return PasskeyLoginResult{}, err
	}
	_, session, err := s.consumePasskeySession(ctx, parsed.Response.CollectedClientData.Challenge)
	if err != nil {
		return PasskeyLoginResult{}, err
	}
	wa, err := s.webAuthn()
	if err != nil {
		return PasskeyLoginResult{}, err
	}
	var user passkeyUser
	var cred *webauthn.Credential
	if len(session.UserID) > 0 {
		user, err = s.passkeyUserByHandle(ctx, session.UserID)
		if err == nil {
			cred, err = wa.ValidateLogin(user, session, parsed)
		}
	} else {
		var webUser webauthn.User
		webUser, cred, err = wa.ValidatePasskeyLogin(func(rawID, userHandle []byte) (webauthn.User, error) {
			return s.passkeyUserByHandle(ctx, userHandle)
		}, session, parsed)
		if err == nil {
			user = webUser.(passkeyUser)
		}
	}
	if err != nil {
		return PasskeyLoginResult{}, err
	}
	if !cred.Flags.UserVerified {
		return PasskeyLoginResult{}, ErrPasskeyUserVerificationRequired
	}
	if cred.Authenticator.CloneWarning && cred.Authenticator.SignCount > 0 {
		return PasskeyLoginResult{}, ErrPasskeyCloneDetected
	}
	if err := s.updatePasskeyAfterUse(ctx, user.id, cred); err != nil {
		return PasskeyLoginResult{}, err
	}
	sid, rt, _, err := s.IssueRefreshSessionWithAuthMethods(ctx, user.id, userAgent, ip, []string{"swk", "mfa"})
	if err != nil {
		return PasskeyLoginResult{UserID: user.id}, err
	}
	token, exp, err := s.IssueAccessToken(ctx, user.id, "", map[string]any{"sid": sid})
	if err != nil {
		return PasskeyLoginResult{}, err
	}
	return PasskeyLoginResult{UserID: user.id, SessionID: sid, RefreshToken: rt, AccessToken: token, ExpiresAt: exp}, nil
}

func (s *Service) ListPasskeys(ctx context.Context, userID string) ([]Passkey, error) {
	rows, err := db.ForSchema(s.pg, s.dbSchema()).Query(ctx, `SELECT id, user_id, transports, authenticator_attachment, backup_eligible, backup_state, label, created_at, last_used_at
FROM profiles.user_passkeys WHERE user_id=$1 AND rpid=$2 AND deleted_at IS NULL ORDER BY created_at ASC, id ASC`, userID, s.opts.PasskeyRPID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Passkey
	for rows.Next() {
		var p Passkey
		if err := rows.Scan(&p.ID, &p.UserID, &p.Transports, &p.AuthenticatorAttachment, &p.BackupEligible, &p.BackupState, &p.Label, &p.CreatedAt, &p.LastUsedAt); err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

func (s *Service) RenamePasskey(ctx context.Context, userID, id, label string) error {
	tag, err := db.ForSchema(s.pg, s.dbSchema()).Exec(ctx, `UPDATE profiles.user_passkeys SET label=$1 WHERE id=$2 AND user_id=$3 AND deleted_at IS NULL`, nullable(strings.TrimSpace(label)), strings.TrimSpace(id), strings.TrimSpace(userID))
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrPasskeyNotFound
	}
	return nil
}

func (s *Service) DeletePasskey(ctx context.Context, userID, id string) error {
	tag, err := db.ForSchema(s.pg, s.dbSchema()).Exec(ctx, `UPDATE profiles.user_passkeys SET deleted_at=NOW() WHERE id=$1 AND user_id=$2 AND deleted_at IS NULL`, strings.TrimSpace(id), strings.TrimSpace(userID))
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrPasskeyNotFound
	}
	return nil
}

func (s *Service) storePasskeySession(ctx context.Context, session *webauthn.SessionData, userID string) error {
	b, err := json.Marshal(session)
	if err != nil {
		return err
	}
	return s.storePasskeyCeremony(ctx, session.Challenge, passkeyCeremonyData{UserID: strings.TrimSpace(userID), Session: b}, passkeyCeremonyTTL)
}

func (s *Service) consumePasskeySession(ctx context.Context, challenge string) (passkeyCeremonyData, webauthn.SessionData, error) {
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

func (s *Service) passkeyUser(ctx context.Context, userID string, createHandle bool) (passkeyUser, error) {
	u, err := s.getUserByID(ctx, userID)
	if err != nil || u == nil {
		return passkeyUser{}, errOrUnauthorized(err)
	}
	if err := s.ensureUserAccess(ctx, u); err != nil {
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

func (s *Service) passkeyUserByHandle(ctx context.Context, handle []byte) (passkeyUser, error) {
	var userID string
	err := db.ForSchema(s.pg, s.dbSchema()).QueryRow(ctx, `SELECT user_id FROM profiles.user_passkey_handles WHERE rpid=$1 AND user_handle=$2`, s.opts.PasskeyRPID, handle).Scan(&userID)
	if err != nil {
		return passkeyUser{}, err
	}
	return s.passkeyUser(ctx, userID, false)
}

func (s *Service) passkeyHandle(ctx context.Context, userID string, create bool) ([]byte, error) {
	var handle []byte
	err := db.ForSchema(s.pg, s.dbSchema()).QueryRow(ctx, `SELECT user_handle FROM profiles.user_passkey_handles WHERE user_id=$1 AND rpid=$2`, userID, s.opts.PasskeyRPID).Scan(&handle)
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
	err = db.ForSchema(s.pg, s.dbSchema()).QueryRow(ctx, `INSERT INTO profiles.user_passkey_handles (user_id, rpid, user_handle) VALUES ($1, $2, $3) ON CONFLICT (rpid, user_id) DO UPDATE SET user_handle=profiles.user_passkey_handles.user_handle RETURNING user_handle`, userID, s.opts.PasskeyRPID, handle).Scan(&handle)
	return handle, err
}

func (s *Service) passkeyCredentialsByUser(ctx context.Context, userID string) ([]webauthn.Credential, error) {
	rows, err := db.ForSchema(s.pg, s.dbSchema()).Query(ctx, `SELECT credential_id, public_key, sign_count, clone_warning, aaguid, transports, authenticator_attachment, backup_eligible, backup_state, user_present, user_verified, flags, attestation_type, attestation_fmt
FROM profiles.user_passkeys WHERE user_id=$1 AND rpid=$2 AND deleted_at IS NULL`, userID, s.opts.PasskeyRPID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []webauthn.Credential
	for rows.Next() {
		cred, err := scanWebAuthnCredential(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, cred)
	}
	return out, rows.Err()
}

type credentialScanner interface {
	Scan(dest ...any) error
}

func scanWebAuthnCredential(row credentialScanner) (webauthn.Credential, error) {
	var (
		credentialID, publicKey, aaguid, flags []byte
		transports                             []string
		attachment, attType, attFmt            string
		signCount                              int64
		clone, be, bs, up, uv                  bool
	)
	if err := row.Scan(&credentialID, &publicKey, &signCount, &clone, &aaguid, &transports, &attachment, &be, &bs, &up, &uv, &flags, &attType, &attFmt); err != nil {
		return webauthn.Credential{}, err
	}
	var transport []protocol.AuthenticatorTransport
	for _, t := range transports {
		transport = append(transport, protocol.AuthenticatorTransport(t))
	}
	credFlags := webauthn.CredentialFlags{UserPresent: up, UserVerified: uv, BackupEligible: be, BackupState: bs}
	if len(flags) > 0 {
		credFlags = webauthn.NewCredentialFlags(protocol.AuthenticatorFlags(flags[0]))
	}
	return webauthn.Credential{
		ID:                credentialID,
		PublicKey:         publicKey,
		AttestationType:   attType,
		AttestationFormat: attFmt,
		Transport:         transport,
		Flags:             credFlags,
		Authenticator: webauthn.Authenticator{
			AAGUID:       aaguid,
			SignCount:    uint32(signCount),
			CloneWarning: clone,
			Attachment:   protocol.AuthenticatorAttachment(attachment),
		},
	}, nil
}

func (s *Service) createPasskey(ctx context.Context, userID string, cred *webauthn.Credential, label *string) (Passkey, error) {
	var p Passkey
	err := db.ForSchema(s.pg, s.dbSchema()).QueryRow(ctx, `INSERT INTO profiles.user_passkeys
(user_id, rpid, credential_id, public_key, sign_count, clone_warning, aaguid, transports, authenticator_attachment, backup_eligible, backup_state, user_present, user_verified, flags, attestation_type, attestation_fmt, label)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17)
RETURNING id, user_id, transports, authenticator_attachment, backup_eligible, backup_state, label, created_at, last_used_at`,
		userID, s.opts.PasskeyRPID, cred.ID, cred.PublicKey, int64(cred.Authenticator.SignCount), cred.Authenticator.CloneWarning, nullBytes(cred.Authenticator.AAGUID),
		transportStrings(cred.Transport), string(cred.Authenticator.Attachment), cred.Flags.BackupEligible, cred.Flags.BackupState, cred.Flags.UserPresent, cred.Flags.UserVerified,
		[]byte{byte(cred.Flags.ProtocolValue())}, cred.AttestationType, cred.AttestationFormat, label,
	).Scan(&p.ID, &p.UserID, &p.Transports, &p.AuthenticatorAttachment, &p.BackupEligible, &p.BackupState, &p.Label, &p.CreatedAt, &p.LastUsedAt)
	return p, err
}

func (s *Service) updatePasskeyAfterUse(ctx context.Context, userID string, cred *webauthn.Credential) error {
	tag, err := db.ForSchema(s.pg, s.dbSchema()).Exec(ctx, `UPDATE profiles.user_passkeys
SET sign_count=$1, clone_warning=$2, backup_state=$3, user_present=$4, user_verified=$5, flags=$6, last_used_at=NOW()
WHERE user_id=$7 AND rpid=$8 AND credential_id=$9 AND deleted_at IS NULL`,
		int64(cred.Authenticator.SignCount), cred.Authenticator.CloneWarning, cred.Flags.BackupState, cred.Flags.UserPresent, cred.Flags.UserVerified, []byte{byte(cred.Flags.ProtocolValue())}, userID, s.opts.PasskeyRPID, cred.ID)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrPasskeyNotFound
	}
	return nil
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

// userIDByLoginIdentifier was removed with the AK2-PK-002 fix: BeginPasskeyLogin no
// longer resolves an identifier to a user (doing so leaked existence + credential
// IDs via the assertion's allowCredentials). Passkey login is now always
// discoverable; the user is resolved at finish from the asserted credential.
