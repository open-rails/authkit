package authcore

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/open-rails/authkit/password"
)

// importTestService builds a DB-backed Service for ImportUsers tests. Skips
// without AUTHKIT_TEST_DATABASE_URL (via testPG).
func importTestService(t *testing.T) (*Service, context.Context) {
	t.Helper()
	pool := testPG(t)
	return NewService(Options{Issuer: "https://test"}, Keyset{}, WithPostgres(pool)), context.Background()
}

// uniq returns identity material unique per test run (the test DB persists).
func uniq() (user func(tag string) string, email func(tag string) string) {
	n := time.Now().UnixNano()
	user = func(tag string) string { return fmt.Sprintf("imp%s%d", tag, n) }
	email = func(tag string) string { return fmt.Sprintf("imp%s%d@example.com", tag, n) }
	return
}

func TestImportUsers_BasicInsert(t *testing.T) {
	svc, ctx := importTestService(t)
	u, e := uniq()
	inputs := []ImportUserInput{
		{Username: u("a"), Email: e("a"), EmailVerified: true},
		{Username: u("b"), Email: e("b")},
		{Username: u("c"), Email: e("c")},
	}
	res, err := svc.ImportUsers(ctx, inputs)
	if err != nil {
		t.Fatalf("ImportUsers: %v", err)
	}
	if res.Inserted != 3 || res.Skipped != 0 || res.Rejected != 0 {
		t.Fatalf("counts = inserted %d skipped %d rejected %d; want 3/0/0", res.Inserted, res.Skipped, res.Rejected)
	}
	for i, r := range res.Results {
		if r.Status != ImportStatusInserted {
			t.Fatalf("row %d status %q want inserted (reason %q)", i, r.Status, r.Reason)
		}
		if r.UserID == "" {
			t.Fatalf("row %d missing UserID", i)
		}
		if got, err := svc.getUserByUsername(ctx, inputs[i].Username); err != nil || got == nil {
			t.Fatalf("row %d user not found after import: %v", i, err)
		}
	}
}

func TestImportUsers_InBatchDedup(t *testing.T) {
	svc, ctx := importTestService(t)
	u, e := uniq()
	dup := u("dup")
	inputs := []ImportUserInput{
		{Username: dup, Email: e("d1")},
		{Username: dup, Email: e("d2")}, // same username as row 0
	}
	res, err := svc.ImportUsers(ctx, inputs)
	if err != nil {
		t.Fatalf("ImportUsers: %v", err)
	}
	if res.Inserted != 1 || res.Skipped != 1 {
		t.Fatalf("counts = inserted %d skipped %d; want 1/1", res.Inserted, res.Skipped)
	}
	if res.Results[0].Status != ImportStatusInserted {
		t.Fatalf("row 0 status %q want inserted", res.Results[0].Status)
	}
	if res.Results[1].Status != ImportStatusSkipped || res.Results[1].Reason != "duplicate_in_batch" {
		t.Fatalf("row 1 = %q/%q want skipped/duplicate_in_batch", res.Results[1].Status, res.Results[1].Reason)
	}
}

func TestImportUsers_SkipExistingIdempotent(t *testing.T) {
	svc, ctx := importTestService(t)
	u, e := uniq()
	inputs := []ImportUserInput{
		{Username: u("x"), Email: e("x")},
		{Username: u("y"), Email: e("y")},
	}
	res1, err := svc.ImportUsers(ctx, inputs)
	if err != nil || res1.Inserted != 2 {
		t.Fatalf("first import: inserted %d err %v; want 2", res1.Inserted, err)
	}
	// Re-run the exact same batch: must be fully idempotent (all skipped, none re-inserted).
	res2, err := svc.ImportUsers(ctx, inputs)
	if err != nil {
		t.Fatalf("second import: %v", err)
	}
	if res2.Inserted != 0 || res2.Skipped != 2 {
		t.Fatalf("re-run counts = inserted %d skipped %d; want 0/2 (idempotent)", res2.Inserted, res2.Skipped)
	}
	for i, r := range res2.Results {
		if r.Status != ImportStatusSkipped || r.Reason != "already_exists" {
			t.Fatalf("re-run row %d = %q/%q want skipped/already_exists", i, r.Status, r.Reason)
		}
	}
}

func TestImportUsers_RejectIsolation(t *testing.T) {
	svc, ctx := importTestService(t)
	u, e := uniq()
	inputs := []ImportUserInput{
		{Username: u("ok1"), Email: e("ok1")},
		{Username: "ab", Email: e("badname")},  // username too short -> rejected
		{Username: u("ok2"), Email: "not-an-email"}, // bad email -> rejected
		{Username: u("ok3"), Email: e("ok3")},
	}
	res, err := svc.ImportUsers(ctx, inputs)
	if err != nil {
		t.Fatalf("ImportUsers: %v", err)
	}
	if res.Inserted != 2 || res.Rejected != 2 {
		t.Fatalf("counts = inserted %d rejected %d; want 2/2 (one bad row must not abort the batch)", res.Inserted, res.Rejected)
	}
	if res.Results[0].Status != ImportStatusInserted || res.Results[3].Status != ImportStatusInserted {
		t.Fatalf("valid rows not inserted: %q, %q", res.Results[0].Status, res.Results[3].Status)
	}
	if res.Results[1].Status != ImportStatusRejected || res.Results[2].Status != ImportStatusRejected {
		t.Fatalf("invalid rows not rejected: %q, %q", res.Results[1].Status, res.Results[2].Status)
	}
}

func TestImportUsers_PasswordImportAndLogin(t *testing.T) {
	svc, ctx := importTestService(t)
	u, e := uniq()
	hash, err := password.HashArgon2id("s3cret-pw-value")
	if err != nil {
		t.Fatalf("hash: %v", err)
	}
	inputs := []ImportUserInput{
		{Username: u("pw"), Email: e("pw"), PasswordHash: hash, HashAlgo: "argon2id"},
	}
	res, err := svc.ImportUsers(ctx, inputs)
	if err != nil || res.Inserted != 1 {
		t.Fatalf("import: inserted %d err %v; want 1", res.Inserted, err)
	}
	userID := res.Results[0].UserID
	if !svc.VerifyUserPassword(ctx, userID, "s3cret-pw-value") {
		t.Fatalf("imported password hash does not verify the original plaintext")
	}
	if svc.VerifyUserPassword(ctx, userID, "wrong-password") {
		t.Fatalf("wrong password unexpectedly verified")
	}
}
