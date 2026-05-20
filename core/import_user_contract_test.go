package core

import (
	"reflect"
	"strings"
	"testing"
)

func TestImportUserContractKeepsAuthKitInChargeOfUserID(t *testing.T) {
	if _, ok := reflect.TypeOf(ImportUserInput{}).FieldByName("ID"); ok {
		t.Fatalf("ImportUserInput must not let host applications choose profiles.users.id")
	}

	src := readSource(t, "service.go")
	for _, marker := range []string{
		"func (s *Service) ImportUser(ctx context.Context, input ImportUserInput)",
		"userID, err := newUUIDV7String()",
		"func (s *Service) UpdateImportedUser(ctx context.Context, userID string, input ImportUserInput)",
		"metadata = COALESCE(metadata, '{}'::jsonb) || $11::jsonb",
		"ensurePersonalOrgForUser(ctx, userID, username)",
		"func (s *Service) UpsertRoleBySlug(ctx context.Context, name, slug string, description *string) error",
	} {
		if !strings.Contains(src, marker) {
			t.Fatalf("expected service.go to contain %q", marker)
		}
	}
}
