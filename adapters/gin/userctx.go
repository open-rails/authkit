package authgin

import (
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v5/pgxpool"
)

// UserContext is a richer, typed view of the authenticated user for handlers.
// It combines JWT claims with fresh DB lookups where appropriate.
type UserContext struct {
	// Identity
	UserID          string  `json:"user_id"`
	Email           string  `json:"email"`
	Username        *string `json:"username,omitempty"`
	DiscordUsername *string `json:"discord_username,omitempty"`
	Language        string  `json:"language"`

	// Access / profile
	Roles        []string `json:"roles,omitempty"`
	Entitlements []string `json:"entitlements,omitempty"`
}

// context key (unexported)
type userCtxKey struct{}

// SetUserContext stores a UserContext on the Gin context for reuse.
func SetUserContext(c *gin.Context, uc UserContext) {
	c.Set("auth.userctx", uc)
}

// GetUserContext returns a previously computed UserContext and a bool.
func GetUserContext(c *gin.Context) (UserContext, bool) {
	if v, ok := c.Get("auth.userctx"); ok {
		if uc, ok := v.(UserContext); ok {
			return uc, true
		}
	}
	return UserContext{}, false
}

// BuildUserContext builds UserContext via a single joined query against Postgres.
// Requires a verified user claim set by an auth gate; otherwise returns Language only.
func BuildUserContext(c *gin.Context, pg *pgxpool.Pool) UserContext {
	lang := parseAcceptLanguage(c.GetHeader("Accept-Language"))
	cl, ok := ClaimsFromGin(c)
	if !ok || cl.UserID == "" {
		return UserContext{Language: lang}
	}
	uc := UserContext{UserID: cl.UserID, Language: lang}
	if pg == nil {
		return uc
	}

	row := pg.QueryRow(c.Request.Context(), `
        WITH roles AS (
            SELECT COALESCE(array_agg(r.slug ORDER BY r.slug), ARRAY[]::text[]) AS slugs
            FROM profiles.user_roles ur
            JOIN profiles.roles r ON ur.role_id = r.id
            WHERE ur.user_id = $1 AND r.deleted_at IS NULL
        ), discord AS (
            SELECT profile->>'username' AS uname
            FROM profiles.user_providers
            WHERE user_id = $1 AND provider_slug = 'discord'
            ORDER BY created_at DESC
            LIMIT 1
        )
        SELECT u.email,
               u.username,
               (SELECT slugs FROM roles),
               COALESCE(u.discord_username, (SELECT uname FROM discord)) AS discord_username
        FROM profiles.users u
        WHERE u.id = $1
    `, cl.UserID)

	var email string
	var username *string
	var roles []string
	var discordUname *string
	if err := row.Scan(&email, &username, &roles, &discordUname); err == nil {
		uc.Email = email
		uc.Username = username
		uc.Roles = roles

		// Entitlements come from JWT claims (populated when token was issued via EntitlementsProvider)
		// For fresh entitlements, consumers should re-issue the token
		uc.Entitlements = cl.Entitlements

		if discordUname != nil && strings.TrimSpace(*discordUname) != "" {
			uc.DiscordUsername = discordUname
		}
	}
	return uc
}

// Safe: no-op without verified claims.
// LookupDBUser enriches the Gin context with DB-backed user details.
func LookupDBUser(pg *pgxpool.Pool) gin.HandlerFunc {
	return func(c *gin.Context) {
		// If we've already built and attached a UserContext in this chain, skip re-enrichment.
		if existing, ok := GetUserContext(c); ok && existing.UserID != "" {
			c.Next()
			return
		}
		if cl, ok := ClaimsFromGin(c); !ok || cl.UserID == "" {
			c.Next()
			return
		}

		uc := BuildUserContext(c, pg)
		SetUserContext(c, uc)
		// Overwrite/augment JWT-attached keys so handlers can rely on a single shape
		if uc.Email != "" {
			c.Set("auth.email", uc.Email)
		}

		c.Set("auth.roles", uc.Roles)
		c.Set("auth.entitlements", uc.Entitlements)
		if uc.DiscordUsername != nil {
			c.Set("auth.discord_username", *uc.DiscordUsername)
		}

		if uc.Language != "" {
			c.Set("auth.language", uc.Language)
		}

		c.Next()
	}
}

// UserContextMiddlewareRequired aborts with 401 if no verified claims are present.
// LookupDBUserRequired requires verified claims, then enriches from DB.
// LookupDBUserRequired was a stricter variant that 401'd when no verified
// claims were present. Prefer composing auth.Required() then LookupDBUser(pg)
// in route registrations for clarity and single-responsibility.

// Convenience helpers
func (uc UserContext) IsLoggedIn() bool { return strings.TrimSpace(uc.UserID) != "" }

func (uc UserContext) IsAdmin() bool { return hasString(uc.Roles, "admin") }

func (uc UserContext) HasRole(role string) bool { return hasString(uc.Roles, role) }

func (uc UserContext) HasEntitlement(ent string) bool { return hasString(uc.Entitlements, ent) }

func hasString(arr []string, want string) bool {
	for _, s := range arr {
		if strings.EqualFold(s, want) {
			return true
		}
	}
	return false
}

// parseAcceptLanguage extracts the primary language (e.g., "en" from "en-US").
func parseAcceptLanguage(header string) string {
	if header == "" {
		return "en"
	}
	// Take the first comma-separated entry, then trim parameters
	part := header
	if i := strings.IndexByte(part, ','); i >= 0 {
		part = part[:i]
	}
	if i := strings.IndexByte(part, ';'); i >= 0 {
		part = part[:i]
	}
	part = strings.TrimSpace(part)
	if part == "" {
		return "en"
	}
	// Reduce region subtags to primary language
	if i := strings.IndexByte(part, '-'); i >= 0 {
		part = part[:i]
	}
	part = strings.ToLower(part)
	if len(part) < 2 {
		return "en"
	}
	return part
}
