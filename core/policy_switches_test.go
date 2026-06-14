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
	if opts.OrgRegistrationMode != RegistrationModeOpen {
		t.Fatalf("OrgRegistrationMode should default to open")
	}
	if !opts.PublicNativeUserRegistrationEnabled() {
		t.Fatalf("PublicNativeUserRegistrationEnabled should default to true")
	}
	if !opts.PublicOrgRegistrationEnabled() {
		t.Fatalf("PublicOrgRegistrationEnabled should default to true")
	}
}

func TestPolicySwitches_Plumbed(t *testing.T) {
	cfg := baseTestConfig(t)
	cfg.NativeUserRegistrationMode = RegistrationModeAdminBootstrapOnly
	cfg.OrgRegistrationMode = RegistrationModeManifestOnly
	svc, err := NewFromConfig(cfg)
	if err != nil {
		t.Fatalf("NewFromConfig: %v", err)
	}
	opts := svc.Options()
	if opts.NativeUserRegistrationMode != RegistrationModeAdminBootstrapOnly {
		t.Fatalf("NativeUserRegistrationMode not plumbed through NewFromConfig")
	}
	if opts.OrgRegistrationMode != RegistrationModeManifestOnly {
		t.Fatalf("OrgRegistrationMode not plumbed through NewFromConfig")
	}
	if opts.PublicNativeUserRegistrationEnabled() {
		t.Fatalf("PublicNativeUserRegistrationEnabled should be false when disabled")
	}
	if opts.PublicOrgRegistrationEnabled() {
		t.Fatalf("PublicOrgRegistrationEnabled should be false when disabled")
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
				OrgRegistrationMode:        mode,
			}
			svc := NewService(opts, Keyset{})
			got := svc.Options()
			if got.PublicNativeUserRegistrationEnabled() {
				t.Fatalf("native public registration should be disabled for %q", mode)
			}
			if got.PublicOrgRegistrationEnabled() {
				t.Fatalf("org public registration should be disabled for %q", mode)
			}
		})
	}
}

func TestPolicySwitches_DeploymentModeMatrix(t *testing.T) {
	tests := []struct {
		name                  string
		nativeMode            RegistrationMode
		orgMode               RegistrationMode
		wantPublicNativeUsers bool
		wantPublicOrgs        bool
		wantPersonalOrgAuto   bool
	}{
		{
			name:                  "doujins-hentai0-native-app",
			nativeMode:            RegistrationModeOpen,
			orgMode:               RegistrationModeClosed,
			wantPublicNativeUsers: true,
			wantPublicOrgs:        false,
		},
		{
			name:           "tensorhub-b2b-admin-created",
			nativeMode:     RegistrationModeAdminOnly,
			orgMode:        RegistrationModeAdminBootstrapOnly,
			wantPublicOrgs: false,
		},
		{
			name:           "openrails-relying-party-closed",
			nativeMode:     RegistrationModeClosed,
			orgMode:        RegistrationModeManifestOnly,
			wantPublicOrgs: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			svc := NewService(Options{
				Issuer:                     "https://test",
				NativeUserRegistrationMode: tt.nativeMode,
				OrgRegistrationMode:        tt.orgMode,
			}, Keyset{})
			opts := svc.Options()
			if opts.PublicNativeUserRegistrationEnabled() != tt.wantPublicNativeUsers {
				t.Fatalf("PublicNativeUserRegistrationEnabled=%v, want %v", opts.PublicNativeUserRegistrationEnabled(), tt.wantPublicNativeUsers)
			}
			if opts.PublicOrgRegistrationEnabled() != tt.wantPublicOrgs {
				t.Fatalf("PublicOrgRegistrationEnabled=%v, want %v", opts.PublicOrgRegistrationEnabled(), tt.wantPublicOrgs)
			}
			if opts.AutoCreatePersonalOrgsEnabled() != tt.wantPersonalOrgAuto {
				t.Fatalf("AutoCreatePersonalOrgsEnabled=%v, want %v", opts.AutoCreatePersonalOrgsEnabled(), tt.wantPersonalOrgAuto)
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

func TestPolicySwitches_NativeUsersDoNotCreatePersonalOrgsByDefault(t *testing.T) {
	pool := testPG(t)
	ctx := context.Background()
	const username = "orglessuser"
	_, _ = pool.Exec(ctx, `DELETE FROM profiles.users WHERE username=$1`, username)
	_, _ = pool.Exec(ctx, `DELETE FROM profiles.orgs WHERE slug=$1`, username)
	t.Cleanup(func() {
		_, _ = pool.Exec(ctx, `DELETE FROM profiles.users WHERE username=$1`, username)
		_, _ = pool.Exec(ctx, `DELETE FROM profiles.orgs WHERE slug=$1`, username)
	})

	svc := NewService(Options{Issuer: "https://test"}, Keyset{}).WithPostgres(pool)
	u, err := svc.CreateUser(ctx, "", username)
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	var count int
	if err := pool.QueryRow(ctx, `
		SELECT COUNT(*)
		FROM profiles.orgs
		WHERE owner_user_id=$1::uuid
		  AND is_personal=true
		  AND deleted_at IS NULL
	`, u.ID).Scan(&count); err != nil {
		t.Fatalf("count personal orgs: %v", err)
	}
	if count != 0 {
		t.Fatalf("expected no default personal org, got %d", count)
	}
}

func TestPolicySwitches_AutoCreatePersonalOrgsOptIn(t *testing.T) {
	pool := testPG(t)
	ctx := context.Background()
	const username = "personalorguser"
	_, _ = pool.Exec(ctx, `DELETE FROM profiles.users WHERE username=$1`, username)
	_, _ = pool.Exec(ctx, `DELETE FROM profiles.orgs WHERE slug=$1`, username)
	t.Cleanup(func() {
		_, _ = pool.Exec(ctx, `DELETE FROM profiles.users WHERE username=$1`, username)
		_, _ = pool.Exec(ctx, `DELETE FROM profiles.orgs WHERE slug=$1`, username)
	})

	svc := NewService(Options{
		Issuer:                 "https://test",
		AutoCreatePersonalOrgs: true,
	}, Keyset{}).WithPostgres(pool)
	u, err := svc.CreateUser(ctx, "", username)
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	var count int
	if err := pool.QueryRow(ctx, `
		SELECT COUNT(*)
		FROM profiles.orgs
		WHERE owner_user_id=$1::uuid
		  AND is_personal=true
		  AND deleted_at IS NULL
	`, u.ID).Scan(&count); err != nil {
		t.Fatalf("count personal orgs: %v", err)
	}
	if count != 1 {
		t.Fatalf("expected opted-in personal org, got %d", count)
	}
}

func TestPolicySwitches_ClosedRelyingPartyAcceptsDelegatedUsersWithoutNativeUsers(t *testing.T) {
	pool := testPG(t)
	ctx := context.Background()
	const (
		slug   = "closed-relying-party"
		issuer = "https://closed-relying-party.example"
	)

	_, _ = pool.Exec(ctx, `DELETE FROM profiles.orgs WHERE slug=$1`, slug)
	t.Cleanup(func() {
		_, _ = pool.Exec(ctx, `DELETE FROM profiles.orgs WHERE slug=$1`, slug)
	})

	var usersBefore int
	if err := pool.QueryRow(ctx, `SELECT COUNT(*) FROM profiles.users`).Scan(&usersBefore); err != nil {
		t.Fatalf("count users before: %v", err)
	}

	svc := NewService(Options{
		Issuer:                     "https://test",
		NativeUserRegistrationMode: RegistrationModeClosed,
		OrgRegistrationMode:        RegistrationModeManifestOnly,
	}, Keyset{}).WithPostgres(pool)
	org, err := svc.CreateOrg(ctx, slug)
	if err != nil {
		t.Fatalf("bootstrap CreateOrg: %v", err)
	}
	t.Cleanup(func() { _, _ = pool.Exec(ctx, `DELETE FROM profiles.remote_applications WHERE slug=$1`, slug) })
	if _, err := svc.UpsertRemoteApplication(ctx, RemoteApplication{
		Slug:      slug,
		OrgID:     org.ID,
		Issuer:    issuer,
		JWKSURI:   issuer + "/.well-known/jwks.json",
		Audiences: []string{"openrails"},
		Enabled:   true,
	}); err != nil {
		t.Fatalf("UpsertRemoteApplication: %v", err)
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
