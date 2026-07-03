package authcore

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	authkit "github.com/open-rails/authkit"
)

// mkBareUser inserts a username-only user and returns its id, with cleanup.
func mkBareUser(t *testing.T, ctx context.Context, svc *Service, tag string) string {
	t.Helper()
	uname := fmt.Sprintf("link-%s-%d", tag, time.Now().UnixNano())
	var id string
	if err := svc.pg.QueryRow(ctx, `INSERT INTO profiles.users (username) VALUES ($1) RETURNING id::text`, uname).Scan(&id); err != nil {
		t.Fatalf("create user: %v", err)
	}
	t.Cleanup(func() { _, _ = svc.pg.Exec(ctx, `DELETE FROM profiles.users WHERE id=$1::uuid`, id) })
	return id
}

// providerOwner returns the (user_id, email_at_provider, provider_slug) of the
// user_providers row for (issuer, subject).
func (s *Service) providerOwner(t *testing.T, ctx context.Context, issuer, subject string) (userID, email, slug string) {
	t.Helper()
	var em, sl *string
	if err := s.pg.QueryRow(ctx,
		`SELECT user_id::text, email_at_provider, provider_slug FROM profiles.user_providers WHERE issuer=$1 AND subject=$2`,
		issuer, subject).Scan(&userID, &em, &sl); err != nil {
		t.Fatalf("lookup provider row: %v", err)
	}
	if em != nil {
		email = *em
	}
	if sl != nil {
		slug = *sl
	}
	return
}

// A subject already linked to user B cannot be claimed by user A: the upsert is
// constrained to the same user_id, so the cross-user attempt returns
// ErrProviderAlreadyLinked and B's row is left untouched (no cross-user write).
func TestLinkProviderByIssuer_CrossUserRejected(t *testing.T) {
	pool := testPG(t)
	ctx := context.Background()
	svc := NewService(Config{Token: TokenConfig{Issuer: "https://test"}}, Keyset{}, WithPostgres(pool))

	a := mkBareUser(t, ctx, svc, "a")
	b := mkBareUser(t, ctx, svc, "b")
	issuer := "https://discord.example"
	subject := fmt.Sprintf("shared-%d", time.Now().UnixNano())
	bEmail := "b@example.com"

	if err := svc.LinkProviderByIssuer(ctx, b, issuer, "discord", subject, &bEmail); err != nil {
		t.Fatalf("link to B: %v", err)
	}

	aEmail := "a@example.com"
	err := svc.LinkProviderByIssuer(ctx, a, issuer, "discord", subject, &aEmail)
	if !errors.Is(err, authkit.ErrProviderAlreadyLinked) {
		t.Fatalf("cross-user link must return ErrProviderAlreadyLinked, got %v", err)
	}

	owner, email, _ := svc.providerOwner(t, ctx, issuer, subject)
	if owner != b {
		t.Fatalf("subject must still belong to B (%s), got %s", b, owner)
	}
	if email != bEmail {
		t.Fatalf("B's email_at_provider must be unchanged (%q), got %q", bEmail, email)
	}
}

// Re-linking the same (issuer, subject) for the SAME user updates email/slug and
// stays a single row (idempotent).
func TestLinkProviderByIssuer_SameUserIdempotent(t *testing.T) {
	pool := testPG(t)
	ctx := context.Background()
	svc := NewService(Config{Token: TokenConfig{Issuer: "https://test"}}, Keyset{}, WithPostgres(pool))

	a := mkBareUser(t, ctx, svc, "idem")
	issuer := "https://google.example"
	subject := fmt.Sprintf("subj-%d", time.Now().UnixNano())

	e1 := "first@example.com"
	if err := svc.LinkProviderByIssuer(ctx, a, issuer, "google", subject, &e1); err != nil {
		t.Fatalf("first link: %v", err)
	}
	e2 := "second@example.com"
	if err := svc.LinkProviderByIssuer(ctx, a, issuer, "google", subject, &e2); err != nil {
		t.Fatalf("re-link: %v", err)
	}

	if got := svc.providerCount(t, ctx, a); got != 1 {
		t.Fatalf("re-link must stay one row, got %d", got)
	}
	owner, email, _ := svc.providerOwner(t, ctx, issuer, subject)
	if owner != a || email != e2 {
		t.Fatalf("re-link should update email to %q for A; got owner=%s email=%q", e2, owner, email)
	}
}

// Switching subjects for the same user+issuer removes the old subject and installs
// the new one in one transaction (exactly one row remains).
func TestLinkProviderByIssuer_SubjectSwitchAtomic(t *testing.T) {
	pool := testPG(t)
	ctx := context.Background()
	svc := NewService(Config{Token: TokenConfig{Issuer: "https://test"}}, Keyset{}, WithPostgres(pool))

	a := mkBareUser(t, ctx, svc, "switch")
	issuer := "https://discord.example"
	subjOld := fmt.Sprintf("old-%d", time.Now().UnixNano())
	subjNew := fmt.Sprintf("new-%d", time.Now().UnixNano())

	if err := svc.LinkProviderByIssuer(ctx, a, issuer, "discord", subjOld, nil); err != nil {
		t.Fatalf("link old subject: %v", err)
	}
	if err := svc.LinkProviderByIssuer(ctx, a, issuer, "discord", subjNew, nil); err != nil {
		t.Fatalf("switch subject: %v", err)
	}

	if got := svc.providerCount(t, ctx, a); got != 1 {
		t.Fatalf("subject switch must leave exactly one row, got %d", got)
	}
	if owner, _, _ := svc.providerOwner(t, ctx, issuer, subjNew); owner != a {
		t.Fatalf("new subject must belong to A; got %s", owner)
	}
}
