package authhttp

import (
	"net/http/httptest"
	"testing"

	core "github.com/open-rails/authkit/core"
)

func TestAdminUserListOptionsFromQueryUsesGenericFilters(t *testing.T) {
	r := httptest.NewRequest("GET", "/admin/users?page=2&page_size=25&search=alice&role=moderator&org=acme&status=banned&sort=email&order=asc&entitlement=premium&filter=taggers", nil)
	got := adminUserListOptionsFromQuery(r)

	if got.Page != 2 || got.PageSize != 25 || got.Search != "alice" {
		t.Fatalf("basic paging/search parsed wrong: %+v", got)
	}
	if got.Role != "moderator" || got.OrgSlug != "acme" || got.Status != core.AdminUserStatusBanned {
		t.Fatalf("generic filters parsed wrong: %+v", got)
	}
	if got.Sort != core.AdminUserSortEmail || got.Desc {
		t.Fatalf("sort parsed wrong: %+v", got)
	}
	if got.Entitlement != "premium" {
		t.Fatalf("entitlement = %q, want premium", got.Entitlement)
	}
}
