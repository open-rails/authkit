package main

import (
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"testing"

	"github.com/open-rails/authkit/internal/errmodel"
)

const authUI = "../../../auth-ui/src"

// auth-ui's generated codes are exactly the catalog's.
func TestGeneratedErrorCodesMatchCatalog(t *testing.T) {
	got, err := os.ReadFile(filepath.Join(authUI, "client/generated/error-codes.ts"))
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(errorCodesTS()) {
		t.Fatal("auth-ui/src/client/generated/error-codes.ts is stale: run go generate ./internal/errmodel")
	}
}

// clientCodes are auth-ui's own error keys: local fallbacks, the OIDC
// redirect's access_denied, and the client's popup and session errors.
var clientCodes = []string{"generic", "network", "network_error", "access_denied", "popup_blocked", "popup_closed", "popup_timeout", "session_changed"}

var (
	errorsBlock = regexp.MustCompile(`(?s)\n  errors: \{\n(.*?)\n  \},?\n`)
	errorKey    = regexp.MustCompile(`(?m)^    "?([A-Za-z0-9_]+)"?:`)
)

// Every locale translates the same error keys, and each key is a wire code or
// one of the client's own: no missing translation, no stale code.
func TestLocalesTranslateCatalogCodes(t *testing.T) {
	known := map[string]bool{}
	for _, c := range errmodel.Codes() {
		known[string(c)] = true
	}
	for _, c := range clientCodes {
		known[c] = true
	}
	var want []string
	for _, locale := range []string{"en", "de", "es", "ja", "ko", "zh"} {
		src, err := os.ReadFile(filepath.Join(authUI, "locales", locale+".ts"))
		if err != nil {
			t.Fatal(err)
		}
		block := errorsBlock.FindSubmatch(src)
		if block == nil {
			t.Fatalf("%s: no top-level errors block", locale)
		}
		var keys []string
		for _, m := range errorKey.FindAllSubmatch(block[1], -1) {
			keys = append(keys, string(m[1]))
		}
		sort.Strings(keys)
		for _, k := range keys {
			if !known[k] {
				t.Errorf("%s: errors.%s is not an AuthKit wire code", locale, k)
			}
		}
		if want == nil {
			want = keys
		} else if !slices.Equal(keys, want) {
			t.Errorf("%s error keys differ from en:\n got %v\nwant %v", locale, keys, want)
		}
	}
}
