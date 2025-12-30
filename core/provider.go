package core

import (
	"context"
	"net"
	"time"

	jwtkit "github.com/PaulFidika/authkit/jwt"
	"github.com/PaulFidika/authkit/siws"
	jwt "github.com/golang-jwt/jwt/v5"
)

// Verifier is the minimal surface needed to validate JWT access tokens.
//
// It intentionally avoids exposing storage/transport details; implementations
// may be fully stateless (JWKS-only) or service-backed.
type Verifier interface {
	JWKS() jwtkit.JWKS
	Keyfunc() func(token *jwt.Token) (any, error)
	Options() Options

	// Optional enrichment hooks (best-effort).
	// Middleware can use these to fetch fresh roles/usernames when available.
	ListRoleSlugsByUser(ctx context.Context, userID string) []string
	GetProviderUsername(ctx context.Context, userID, provider string) (string, error)
}

// Provider is the full auth surface needed by the built-in HTTP handlers.
// It is implemented by *Service and is intended as the template-friendly
// integration boundary for applications.
type Provider interface {
	// 2FA phone setup
	SendPhone2FASetupCode(ctx context.Context, userID, phone, code string) error
	VerifyPhone2FASetupCode(ctx context.Context, userID, phone, code string) (bool, error)
	Verifier
	RequestPhoneChange(ctx context.Context, userID, newPhone string) error
	ConfirmPhoneChange(ctx context.Context, userID, phone, code string) error
	ResendPhoneChangeCode(ctx context.Context, userID, phone string) error

	// Token/session minting
	IssueAccessToken(ctx context.Context, userID, email string, extra map[string]any) (token string, expiresAt time.Time, err error)
	IssueRefreshSession(ctx context.Context, userID, userAgent string, ip net.IP) (sessionID, refreshToken string, expiresAt *time.Time, err error)
	ExchangeRefreshToken(ctx context.Context, refreshToken string, ua string, ip net.IP) (idToken string, expiresAt time.Time, newRefresh string, err error)
	ResolveSessionByRefresh(ctx context.Context, refreshToken string) (string, error)

	// Session management (self-service)
	ListUserSessions(ctx context.Context, userID string) ([]Session, error)
	RevokeSessionByIDForUser(ctx context.Context, userID, sessionID string) error
	RevokeAllSessions(ctx context.Context, userID string, keepSessionID *string) error
	SetUserActive(ctx context.Context, userID string, isActive bool) error

	// Password + registration
	PasswordLogin(ctx context.Context, email, pass string, extra map[string]any) (string, time.Time, error)
	PasswordLoginByUserID(ctx context.Context, userID, pass string, extra map[string]any) (string, time.Time, error)
	ChangePassword(ctx context.Context, userID, current, new string, keepSessionID *string) error
	// AdminSetPassword force-sets a user's password (admin only, no current password required)
	AdminSetPassword(ctx context.Context, userID, new string) error
	HasPassword(ctx context.Context, userID string) bool

	HasEmailSender() bool
	HasSMSSender() bool

	RequestPasswordReset(ctx context.Context, email string, ttl time.Duration) error
	ConfirmPasswordReset(ctx context.Context, token string, newPassword string) (string, error)
	RequestPhonePasswordReset(ctx context.Context, phone string, ttl time.Duration) error
	ConfirmPhonePasswordReset(ctx context.Context, phone, code, newPassword string) (string, error)

	// Email verification
	RequestEmailVerification(ctx context.Context, email string, ttl time.Duration) error
	ConfirmEmailVerification(ctx context.Context, tokenHash string) (string, error)

	// Pending registrations
	GetPendingRegistrationByEmail(ctx context.Context, email string) (*PendingRegistration, error)
	GetPendingPhoneRegistrationByPhone(ctx context.Context, phone string) (*PendingRegistration, error)
	VerifyPendingPassword(ctx context.Context, email, pass string) bool
	CheckPendingRegistrationConflict(ctx context.Context, email, username string) (emailTaken, usernameTaken bool, err error)
	CreatePendingRegistration(ctx context.Context, email, username, passwordHash string, ttl time.Duration) (string, error)
	CheckPhoneRegistrationConflict(ctx context.Context, phone, username string) (phoneTaken, usernameTaken bool, err error)
	CreatePendingPhoneRegistration(ctx context.Context, phone, username, passwordHash string) (string, error)
	ConfirmPendingRegistration(ctx context.Context, token string) (string, error)
	ConfirmPendingPhoneRegistration(ctx context.Context, phone, code string) (string, error)

	// Phone verification (existing users)
	RequestPhoneVerification(ctx context.Context, phone string, ttl time.Duration) error
	SendPhoneVerificationToUser(ctx context.Context, phone, userID string, ttl time.Duration) error

	// Identity lookup/provisioning
	GetUserByEmail(ctx context.Context, email string) (*User, error)
	GetUserByUsername(ctx context.Context, username string) (*User, error)
	GetUserByPhone(ctx context.Context, phone string) (*User, error)
	CreateUser(ctx context.Context, email, username string) (*User, error)
	SetEmailVerified(ctx context.Context, id string, v bool) error
	UpdateUsername(ctx context.Context, id, username string) error
	UpdateEmail(ctx context.Context, id, email string) error
	SetActive(ctx context.Context, id string, active bool) error
	UpdateBiography(ctx context.Context, id string, bio *string) error

	// OIDC/provider links
	GetProviderLink(ctx context.Context, provider, subject string) (string, *string, error)
	GetProviderLinkByIssuer(ctx context.Context, issuer, subject string) (string, *string, error)
	LinkProviderByIssuer(ctx context.Context, userID, issuer, providerSlug, subject string, email *string) error
	SetProviderUsername(ctx context.Context, userID, provider, subject, username string) error
	DeriveUsernameForOAuth(ctx context.Context, provider, preferred, email, displayName string) string

	// Email change
	RequestEmailChange(ctx context.Context, userID, newEmail string) error
	ConfirmEmailChange(ctx context.Context, userID, code string) error
	ResendEmailChangeCode(ctx context.Context, userID string) error

	// 2FA
	Get2FASettings(ctx context.Context, userID string) (*TwoFactorSettings, error)
	Enable2FA(ctx context.Context, userID, method string, phoneNumber *string) ([]string, error)
	Disable2FA(ctx context.Context, userID string) error
	Verify2FACode(ctx context.Context, userID, code string) (bool, error)
	VerifyBackupCode(ctx context.Context, userID, code string) (bool, error)
	RegenerateBackupCodes(ctx context.Context, userID string) ([]string, error)
	Require2FAForLogin(ctx context.Context, userID string) (string, error)

	// Solana SIWS
	GenerateSIWSChallenge(ctx context.Context, cache siws.ChallengeCache, domain, address, username string) (siws.SignInInput, error)
	VerifySIWSAndLogin(ctx context.Context, cache siws.ChallengeCache, output siws.SignInOutput, extra map[string]any) (accessToken string, expiresAt time.Time, refreshToken, userID string, created bool, err error)
	LinkSolanaWallet(ctx context.Context, cache siws.ChallengeCache, userID string, output siws.SignInOutput) error

	// Admin operations
	AdminListUsers(ctx context.Context, page, pageSize int, filter, search string) (*AdminListUsersResult, error)
	AdminGetUser(ctx context.Context, userID string) (*AdminUser, error)
	AdminDeleteUser(ctx context.Context, userID string) error
	AssignRoleBySlug(ctx context.Context, userID, slug string) error
	RemoveRoleBySlug(ctx context.Context, userID, slug string) error
	AdminListUserSessions(ctx context.Context, userID string) ([]Session, error)
	AdminRevokeUserSessions(ctx context.Context, userID string) error
	RevokeSessionByID(ctx context.Context, sessionID string) error
	AdminGetUserSignins(ctx context.Context, userID string, page, pageSize int) ([]SigninEntry, error)

	// Link management
	CountProviderLinks(ctx context.Context, userID string) int
	UnlinkProvider(ctx context.Context, userID, provider string) error

	// Observability hooks
	LogLogin(ctx context.Context, userID string, method string, sessionID string, ip *string, ua *string)
	SendWelcome(ctx context.Context, userID string)
}
