package querytest

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/open-rails/authkit/internal/authcore"
	"github.com/open-rails/authkit/internal/db"
	"github.com/open-rails/authkit/internal/testdb"
)

func TestQueryContracts(t *testing.T) {
	pg := testdb.ScratchPostgres(t)
	ctx := context.Background()
	q := db.New(pg.Pool)

	t.Run("users identity owner namespace and provider links", func(t *testing.T) {
		userID := fixedUUID(1)
		username := "contract-user"
		email := "Contract.User@Example.TEST"
		inserted, err := q.UserInsert(ctx, db.UserInsertParams{ID: userID, Email: email, Username: &username})
		requireNoError(t, err)
		if inserted.ID != userID || inserted.Email == nil || *inserted.Email != "contract.user@example.test" {
			t.Fatalf("inserted user = %+v", inserted)
		}

		byEmail, err := q.UserByEmail(ctx, "contract.user@example.test")
		requireNoError(t, err)
		if byEmail.ID != userID || byEmail.Username == nil || *byEmail.Username != username {
			t.Fatalf("UserByEmail = %+v", byEmail)
		}

		requireNoError(t, q.UserSetPreferredLanguage(ctx, db.UserSetPreferredLanguageParams{ID: userID, PreferredLanguage: ptr("es")}))
		language, err := q.UserPreferredLanguage(ctx, userID)
		requireNoError(t, err)
		if language != "es" {
			t.Fatalf("preferred language = %q", language)
		}

		requireNoError(t, q.UserRenameInsert(ctx, db.UserRenameInsertParams{UserID: userID, FromSlug: username}))
		requireNoError(t, q.UserSetUsername(ctx, db.UserSetUsernameParams{ID: userID, Username: ptr("contract-user-new")}))
		aliases, err := q.UserSlugAliases(ctx, userID)
		requireNoError(t, err)
		if len(aliases) != 1 || aliases[0] != username {
			t.Fatalf("UserSlugAliases = %v", aliases)
		}

		rows, err := q.UserMetadataPatch(ctx, db.UserMetadataPatchParams{ID: userID, Patch: []byte(`{"reserved":true}`)})
		requireNoError(t, err)
		if rows != 1 {
			t.Fatalf("metadata patch rows = %d", rows)
		}
		reserved, err := q.UserIsReserved(ctx, userID)
		requireNoError(t, err)
		if !reserved {
			t.Fatal("UserIsReserved = false")
		}

		providerID := fixedUUID(2)
		providerSlug := "github"
		providerEmail := "linked@example.test"
		_, err = q.UserProviderUpsertByIssuer(ctx, db.UserProviderUpsertByIssuerParams{
			ID: providerID, UserID: userID, Issuer: "https://github.com", ProviderSlug: &providerSlug,
			Subject: "gh-123", EmailAtProvider: &providerEmail,
		})
		requireNoError(t, err)
		link, err := q.ProviderLinkByIssuer(ctx, db.ProviderLinkByIssuerParams{Issuer: "https://github.com", Subject: "gh-123"})
		requireNoError(t, err)
		if link.UserID != userID || link.EmailAtProvider == nil || *link.EmailAtProvider != providerEmail {
			t.Fatalf("ProviderLinkByIssuer = %+v", link)
		}
		count, err := q.UserProvidersCount(ctx, userID)
		requireNoError(t, err)
		if count != 1 {
			t.Fatalf("provider count = %d", count)
		}
	})

	t.Run("sessions rotate revoke and freshness", func(t *testing.T) {
		userID := createUser(t, ctx, q, 10, "session-user")
		issuer := "https://issuer.example"
		expires := time.Now().Add(24 * time.Hour)
		session, err := q.SessionInsert(ctx, db.SessionInsertParams{
			ID: fixedUUID(11), FamilyID: fixedUUID(12), UserID: userID, Issuer: issuer,
			CurrentTokenHash: []byte("current-token"), ExpiresAt: &expires,
			UserAgent: ptr("authkit-test"), IpAddr: ptr("127.0.0.1"), AuthMethods: []string{"pwd"},
		})
		requireNoError(t, err)

		current, err := q.SessionByCurrentTokenHash(ctx, db.SessionByCurrentTokenHashParams{CurrentTokenHash: []byte("current-token"), Issuer: issuer})
		requireNoError(t, err)
		if current.ID != session.ID || current.UserID != userID {
			t.Fatalf("SessionByCurrentTokenHash = %+v", current)
		}

		rows, err := q.SessionMarkAuthenticated(ctx, db.SessionMarkAuthenticatedParams{
			SessionID: session.ID, UserID: userID, Issuer: issuer, AuthMethods: []string{"otp"},
		})
		requireNoError(t, err)
		if rows != 1 {
			t.Fatalf("mark authenticated rows = %d", rows)
		}
		fresh, err := q.SessionFreshSince(ctx, db.SessionFreshSinceParams{SessionID: session.ID, UserID: userID, Issuer: issuer})
		requireNoError(t, err)
		if !contains(fresh.AuthMethods, "pwd") || !contains(fresh.AuthMethods, "otp") {
			t.Fatalf("fresh auth methods = %v", fresh.AuthMethods)
		}

		rows, err = q.SessionRotate(ctx, db.SessionRotateParams{
			ID: session.ID, ExpectedCurrentTokenHash: []byte("current-token"),
			NewTokenHash: []byte("rotated-token"), UserAgent: ptr("authkit-test-2"), IpAddr: ptr("127.0.0.2"),
		})
		requireNoError(t, err)
		if rows != 1 {
			t.Fatalf("rotate rows = %d", rows)
		}
		previous, err := q.SessionByPreviousTokenHash(ctx, db.SessionByPreviousTokenHashParams{PreviousTokenHash: []byte("current-token"), Issuer: issuer})
		requireNoError(t, err)
		if previous.ID != session.ID {
			t.Fatalf("SessionByPreviousTokenHash = %+v", previous)
		}

		active, err := q.SessionsCountActive(ctx, db.SessionsCountActiveParams{UserID: userID, Issuer: issuer})
		requireNoError(t, err)
		if active != 1 {
			t.Fatalf("active sessions = %d", active)
		}
		revokedUser, err := q.SessionRevokeByID(ctx, db.SessionRevokeByIDParams{ID: session.ID, Issuer: issuer})
		requireNoError(t, err)
		if revokedUser != userID {
			t.Fatalf("revoked user = %q", revokedUser)
		}
		_, err = q.SessionByCurrentTokenHash(ctx, db.SessionByCurrentTokenHashParams{CurrentTokenHash: []byte("rotated-token"), Issuer: issuer})
		if !errors.Is(err, pgx.ErrNoRows) {
			t.Fatalf("revoked session lookup err = %v, want no rows", err)
		}
	})

	t.Run("mfa settings factors and replay guards", func(t *testing.T) {
		userID := createUser(t, ctx, q, 20, "mfa-user")
		requireNoError(t, q.MFAUpsertSettings(ctx, db.MFAUpsertSettingsParams{UserID: userID, BackupCodes: []string{"code-a", "code-b"}}))
		settings, err := q.MFASettingsByUser(ctx, userID)
		requireNoError(t, err)
		if !settings.Enabled || len(settings.BackupCodes) != 2 {
			t.Fatalf("MFASettingsByUser = %+v", settings)
		}

		step := int64(100)
		factor, err := q.MFAUpsertFactor(ctx, db.MFAUpsertFactorParams{
			UserID: userID, Method: "totp", TotpSecret: []byte("encrypted-secret"),
			LastTotpStep: &step, IsDefault: true,
		})
		requireNoError(t, err)
		if factor.Method != "totp" || !factor.IsDefault {
			t.Fatalf("MFAUpsertFactor = %+v", factor)
		}

		nextStep := int64(101)
		rows, err := q.MFAConsumeFactorTOTPStep(ctx, db.MFAConsumeFactorTOTPStepParams{ID: factor.ID, UserID: userID, Step: &nextStep})
		requireNoError(t, err)
		if rows != 1 {
			t.Fatalf("consume TOTP step rows = %d", rows)
		}
		rows, err = q.MFAConsumeFactorTOTPStep(ctx, db.MFAConsumeFactorTOTPStepParams{ID: factor.ID, UserID: userID, Step: &nextStep})
		requireNoError(t, err)
		if rows != 0 {
			t.Fatalf("replayed TOTP step rows = %d", rows)
		}

		rows, err = q.MFAConsumeBackupCode(ctx, db.MFAConsumeBackupCodeParams{UserID: userID, CodeHash: "code-a"})
		requireNoError(t, err)
		if rows != 1 {
			t.Fatalf("consume backup code rows = %d", rows)
		}
		rows, err = q.MFAConsumeBackupCode(ctx, db.MFAConsumeBackupCodeParams{UserID: userID, CodeHash: "code-a"})
		requireNoError(t, err)
		if rows != 0 {
			t.Fatalf("replayed backup code rows = %d", rows)
		}
	})

	t.Run("remote applications and permission groups", func(t *testing.T) {
		schema := testGroupSchema(t)
		store := authcore.NewPermissionGroupStore(pg.Pool)
		requireNoError(t, store.SeedContainment(ctx, schema))
		rootID, err := store.CreateGroup(ctx, "root", "", "")
		requireNoError(t, err)
		orgID, err := store.CreateGroup(ctx, "org", rootID, "contract-org")
		requireNoError(t, err)
		repoID, err := store.CreateGroup(ctx, "repo", orgID, "contract-repo")
		requireNoError(t, err)

		userID := createUser(t, ctx, q, 30, "group-user")
		requireNoError(t, store.AssignRole(ctx, orgID, userID, authcore.SubjectKindUser, authcore.OwnerRoleName))
		assignments, err := store.WalkAssignments(ctx, repoID, userID, authcore.SubjectKindUser)
		requireNoError(t, err)
		if len(assignments) != 1 || assignments[0].Persona != "org" || assignments[0].Roles[0] != authcore.OwnerRoleName {
			t.Fatalf("WalkAssignments = %+v", assignments)
		}
		can, err := store.CanOnGroup(ctx, schema, userID, authcore.SubjectKindUser, repoID, "org:repo:read")
		requireNoError(t, err)
		if !can {
			t.Fatal("expected org owner to read repo")
		}

		app, err := q.RemoteApplicationUpsert(ctx, db.RemoteApplicationUpsertParams{
			Slug: "contract-app", PermissionGroupID: &orgID, Issuer: "https://contract-app.example",
			JwksUri: "https://contract-app.example/jwks.json", Mode: "jwks", Enabled: true,
		})
		requireNoError(t, err)
		if app.PermissionGroupID != orgID {
			t.Fatalf("RemoteApplicationUpsert = %+v", app)
		}
		byIssuer, err := q.RemoteApplicationByIssuer(ctx, "https://contract-app.example")
		requireNoError(t, err)
		if byIssuer.ID != app.ID || !byIssuer.Enabled {
			t.Fatalf("RemoteApplicationByIssuer = %+v", byIssuer)
		}
		enabled, err := q.RemoteApplicationsEnabled(ctx)
		requireNoError(t, err)
		if len(enabled) != 1 || enabled[0].Slug != "contract-app" {
			t.Fatalf("RemoteApplicationsEnabled = %+v", enabled)
		}

		attr, err := q.RemoteAppAttributeDefUpsert(ctx, db.RemoteAppAttributeDefUpsertParams{
			RemoteApplicationID: app.ID, Key: "deployment.region", Version: 1, Definition: []byte(`{"type":"string"}`),
		})
		requireNoError(t, err)
		if attr.Key != "deployment.region" || attr.Version != 1 {
			t.Fatalf("RemoteAppAttributeDefUpsert = %+v", attr)
		}
		attrs, err := q.RemoteAppAttributeDefsList(ctx, app.ID)
		requireNoError(t, err)
		if len(attrs) != 1 || attrs[0].Key != attr.Key {
			t.Fatalf("RemoteAppAttributeDefsList = %+v", attrs)
		}
	})
}

func createUser(t *testing.T, ctx context.Context, q *db.Queries, n int, username string) string {
	t.Helper()
	userID := fixedUUID(n)
	_, err := q.UserInsert(ctx, db.UserInsertParams{ID: userID, Email: username + "@example.test", Username: &username})
	requireNoError(t, err)
	return userID
}

func testGroupSchema(t *testing.T) *authcore.GroupSchema {
	t.Helper()
	schema, err := authcore.BuildSchema(
		authcore.PersonaDef{
			Name:  authcore.RootPersona,
			Roles: []authcore.RoleDef{{Name: authcore.OwnerRoleName, Permissions: []string{"root:*"}}},
		},
		authcore.PersonaDef{
			Name: "org", Parent: authcore.RootPersona,
			Roles: []authcore.RoleDef{{Name: authcore.OwnerRoleName, Permissions: []string{"org:*"}}},
		},
		authcore.PersonaDef{
			Name: "repo", Parent: "org",
			Roles: []authcore.RoleDef{{Name: "reader", Permissions: []string{"repo:repo:read"}}},
		},
	)
	requireNoError(t, err)
	return schema
}

func fixedUUID(n int) string {
	return "00000000-0000-4000-8000-" + leftPadHex(n, 12)
}

func leftPadHex(n, width int) string {
	const digits = "0123456789abcdef"
	buf := make([]byte, width)
	for i := range buf {
		buf[i] = '0'
	}
	for i := width - 1; i >= 0 && n > 0; i-- {
		buf[i] = digits[n&0xf]
		n >>= 4
	}
	return string(buf)
}

func ptr[T any](v T) *T { return &v }

func contains(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

func requireNoError(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}
