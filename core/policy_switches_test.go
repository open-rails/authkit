package core

import (
	"context"
	"testing"
)

func TestPolicySwitches_DefaultPreservesCurrentBehavior(t *testing.T) {
	cfg := baseTestConfig(t)
	svc, err := NewFromConfig(cfg)
	if err != nil {
		t.Fatalf("NewFromConfig: %v", err)
	}
	opts := svc.Options()
	if opts.NativeUserRegistrationMode != RegistrationModeOpen {
		t.Fatalf("NativeUserRegistrationMode should default to open")
	}
	if opts.TenantRegistrationMode != RegistrationModeOpen {
		t.Fatalf("TenantRegistrationMode should default to open")
	}
	if !opts.PublicNativeUserRegistrationEnabled() {
		t.Fatalf("PublicNativeUserRegistrationEnabled should default to true")
	}
	if !opts.PublicTenantRegistrationEnabled() {
		t.Fatalf("PublicTenantRegistrationEnabled should default to true")
	}
}

func TestPolicySwitches_Plumbed(t *testing.T) {
	cfg := baseTestConfig(t)
	cfg.NativeUserRegistrationMode = RegistrationModeAdminBootstrapOnly
	cfg.TenantRegistrationMode = RegistrationModeManifestOnly
	svc, err := NewFromConfig(cfg)
	if err != nil {
		t.Fatalf("NewFromConfig: %v", err)
	}
	opts := svc.Options()
	if opts.NativeUserRegistrationMode != RegistrationModeAdminBootstrapOnly {
		t.Fatalf("NativeUserRegistrationMode not plumbed through NewFromConfig")
	}
	if opts.TenantRegistrationMode != RegistrationModeManifestOnly {
		t.Fatalf("TenantRegistrationMode not plumbed through NewFromConfig")
	}
	if opts.PublicNativeUserRegistrationEnabled() {
		t.Fatalf("PublicNativeUserRegistrationEnabled should be false when disabled")
	}
	if opts.PublicTenantRegistrationEnabled() {
		t.Fatalf("PublicTenantRegistrationEnabled should be false when disabled")
	}
}

// CreatePendingRegistration is the core front-door chokepoint for public
// password registration. It must hard-fail with ErrRegistrationDisabled when
// the switch is on, before touching storage.
func TestPolicySwitches_CoreRegistrationGate(t *testing.T) {
	cfg := baseTestConfig(t)
	cfg.NativeUserRegistrationMode = RegistrationModeAdminBootstrapOnly
	svc, err := NewFromConfig(cfg)
	if err != nil {
		t.Fatalf("NewFromConfig: %v", err)
	}
	if _, err := svc.CreatePendingRegistration(t.Context(), "a@b.com", "alice", "hash", 0); err != ErrRegistrationDisabled {
		t.Fatalf("want ErrRegistrationDisabled, got %v", err)
	}
	if _, err := svc.CreatePendingPhoneRegistration(t.Context(), "+12025550123", "alice", "hash"); err != ErrRegistrationDisabled {
		t.Fatalf("want ErrRegistrationDisabled, got %v", err)
	}
}

func TestPolicySwitches_RegistrationModes(t *testing.T) {
	for _, mode := range []RegistrationMode{
		RegistrationModeInviteOnly,
		RegistrationModeAdminOnly,
		RegistrationModeAdminBootstrapOnly,
		RegistrationModeManifestOnly,
		RegistrationModeClosed,
	} {
		t.Run(string(mode), func(t *testing.T) {
			opts := Options{
				NativeUserRegistrationMode: mode,
				TenantRegistrationMode:     mode,
			}
			svc := NewService(opts, Keyset{})
			got := svc.Options()
			if got.PublicNativeUserRegistrationEnabled() {
				t.Fatalf("native public registration should be disabled for %q", mode)
			}
			if got.PublicTenantRegistrationEnabled() {
				t.Fatalf("tenant public registration should be disabled for %q", mode)
			}
		})
	}
}

func TestPolicySwitches_DeploymentModeMatrix(t *testing.T) {
	tests := []struct {
		name                   string
		nativeMode             RegistrationMode
		tenantMode             RegistrationMode
		wantPublicNativeUsers  bool
		wantPublicTenants      bool
		wantPersonalTenantAuto bool
	}{
		{
			name:                  "doujins-hentai0-native-app",
			nativeMode:            RegistrationModeOpen,
			tenantMode:            RegistrationModeClosed,
			wantPublicNativeUsers: true,
			wantPublicTenants:     false,
		},
		{
			name:              "tensorhub-b2b-admin-created",
			nativeMode:        RegistrationModeAdminOnly,
			tenantMode:        RegistrationModeAdminBootstrapOnly,
			wantPublicTenants: false,
		},
		{
			name:              "openrails-relying-party-closed",
			nativeMode:        RegistrationModeClosed,
			tenantMode:        RegistrationModeManifestOnly,
			wantPublicTenants: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			svc := NewService(Options{
				Issuer:                     "https://test",
				TenantMode:                 "multi",
				NativeUserRegistrationMode: tt.nativeMode,
				TenantRegistrationMode:     tt.tenantMode,
			}, Keyset{})
			opts := svc.Options()
			if opts.PublicNativeUserRegistrationEnabled() != tt.wantPublicNativeUsers {
				t.Fatalf("PublicNativeUserRegistrationEnabled=%v, want %v", opts.PublicNativeUserRegistrationEnabled(), tt.wantPublicNativeUsers)
			}
			if opts.PublicTenantRegistrationEnabled() != tt.wantPublicTenants {
				t.Fatalf("PublicTenantRegistrationEnabled=%v, want %v", opts.PublicTenantRegistrationEnabled(), tt.wantPublicTenants)
			}
			if opts.AutoCreatePersonalTenantsEnabled() != tt.wantPersonalTenantAuto {
				t.Fatalf("AutoCreatePersonalTenantsEnabled=%v, want %v", opts.AutoCreatePersonalTenantsEnabled(), tt.wantPersonalTenantAuto)
			}
		})
	}
}

func TestPolicySwitches_RejectsLegacyBootstrapOnlyMode(t *testing.T) {
	cfg := baseTestConfig(t)
	cfg.NativeUserRegistrationMode = RegistrationMode("bootstrap_only")
	if _, err := NewFromConfig(cfg); err == nil {
		t.Fatalf("legacy bootstrap_only mode should be rejected")
	}
}

func TestPolicySwitches_NativeUsersDoNotCreatePersonalTenantsByDefault(t *testing.T) {
	pool := testPG(t)
	ctx := context.Background()
	const username = "tenantlessuser"
	_, _ = pool.Exec(ctx, `DELETE FROM profiles.users WHERE username=$1`, username)
	_, _ = pool.Exec(ctx, `DELETE FROM profiles.tenants WHERE slug=$1`, username)
	t.Cleanup(func() {
		_, _ = pool.Exec(ctx, `DELETE FROM profiles.users WHERE username=$1`, username)
		_, _ = pool.Exec(ctx, `DELETE FROM profiles.tenants WHERE slug=$1`, username)
	})

	svc := NewService(Options{Issuer: "https://test", TenantMode: "multi"}, Keyset{}).WithPostgres(pool)
	u, err := svc.CreateUser(ctx, "", username)
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	var count int
	if err := pool.QueryRow(ctx, `
		SELECT COUNT(*)
		FROM profiles.tenants
		WHERE owner_user_id=$1::uuid
		  AND is_personal=true
		  AND deleted_at IS NULL
	`, u.ID).Scan(&count); err != nil {
		t.Fatalf("count personal tenants: %v", err)
	}
	if count != 0 {
		t.Fatalf("expected no default personal tenant, got %d", count)
	}
}

func TestPolicySwitches_AutoCreatePersonalTenantsOptIn(t *testing.T) {
	pool := testPG(t)
	ctx := context.Background()
	const username = "personaltenantuser"
	_, _ = pool.Exec(ctx, `DELETE FROM profiles.users WHERE username=$1`, username)
	_, _ = pool.Exec(ctx, `DELETE FROM profiles.tenants WHERE slug=$1`, username)
	t.Cleanup(func() {
		_, _ = pool.Exec(ctx, `DELETE FROM profiles.users WHERE username=$1`, username)
		_, _ = pool.Exec(ctx, `DELETE FROM profiles.tenants WHERE slug=$1`, username)
	})

	svc := NewService(Options{
		Issuer:                    "https://test",
		TenantMode:                "multi",
		AutoCreatePersonalTenants: true,
	}, Keyset{}).WithPostgres(pool)
	u, err := svc.CreateUser(ctx, "", username)
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	var count int
	if err := pool.QueryRow(ctx, `
		SELECT COUNT(*)
		FROM profiles.tenants
		WHERE owner_user_id=$1::uuid
		  AND is_personal=true
		  AND deleted_at IS NULL
	`, u.ID).Scan(&count); err != nil {
		t.Fatalf("count personal tenants: %v", err)
	}
	if count != 1 {
		t.Fatalf("expected opted-in personal tenant, got %d", count)
	}
}

func TestPolicySwitches_ClosedRelyingPartyAcceptsDelegatedUsersWithoutNativeUsers(t *testing.T) {
	pool := testPG(t)
	ctx := context.Background()
	const (
		slug    = "closed-relying-party"
		issuer  = "https://closed-relying-party.example"
		subject = "external-user-1"
	)

	_, _ = pool.Exec(ctx, `DELETE FROM profiles.tenants WHERE slug=$1`, slug)
	t.Cleanup(func() {
		_, _ = pool.Exec(ctx, `DELETE FROM profiles.tenants WHERE slug=$1`, slug)
	})

	var usersBefore int
	if err := pool.QueryRow(ctx, `SELECT COUNT(*) FROM profiles.users`).Scan(&usersBefore); err != nil {
		t.Fatalf("count users before: %v", err)
	}

	svc := NewService(Options{
		Issuer:                     "https://test",
		TenantMode:                 "multi",
		NativeUserRegistrationMode: RegistrationModeClosed,
		TenantRegistrationMode:     RegistrationModeManifestOnly,
	}, Keyset{}).WithPostgres(pool)
	if _, err := svc.CreateTenant(ctx, slug); err != nil {
		t.Fatalf("bootstrap CreateTenant: %v", err)
	}
	if _, err := svc.UpsertTenantIssuer(ctx, TenantIssuer{
		TenantSlug: slug,
		Issuer:     issuer,
		JWKSURI:    issuer + "/.well-known/jwks.json",
		Audiences:  []string{"openrails"},
		Enabled:    true,
	}); err != nil {
		t.Fatalf("UpsertTenantIssuer: %v", err)
	}
	if _, err := svc.TouchDelegatedUser(ctx, slug, issuer, subject); err != nil {
		t.Fatalf("TouchDelegatedUser: %v", err)
	}
	if _, err := svc.CreatePendingRegistration(ctx, "blocked@example.com", "blockeduser", "hash", 0); err != ErrRegistrationDisabled {
		t.Fatalf("closed native registration should reject public user creation, got %v", err)
	}

	var usersAfter int
	if err := pool.QueryRow(ctx, `SELECT COUNT(*) FROM profiles.users`).Scan(&usersAfter); err != nil {
		t.Fatalf("count users after: %v", err)
	}
	if usersAfter != usersBefore {
		t.Fatalf("delegated relying-party path created native users: before=%d after=%d", usersBefore, usersAfter)
	}
}
