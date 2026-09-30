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

const repo = "../../.."

func init() { repoRoot = repo }

// Every generated file matches the catalogs it is generated from.
func TestGeneratedContractIsFresh(t *testing.T) {
	want, err := files()
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range sortedKeys(want) {
		got, err := os.ReadFile(filepath.Join(repo, name))
		if err != nil {
			t.Fatal(err)
		}
		if string(got) != string(want[name]) {
			t.Errorf("%s is stale: run go generate ./internal/httpapi", name)
		}
	}
}

// clientCodes are auth-ui's own error keys: local fallbacks, the OIDC
// redirect's access_denied, and the client's popup and session errors.
var clientCodes = []string{"generic", "network", "network_error", "access_denied", "popup_blocked", "popup_closed", "popup_timeout", "session_changed"}

var (
	errorsBlock = regexp.MustCompile(`(?s)\n  errors: \{\n(.*?)\n  \},?\n`)
	errorKey    = regexp.MustCompile(`(?m)^    "?([A-Za-z0-9_]+)"?:`)
)

// English error messages come from the Go catalog (generated
// AUTH_ERROR_MESSAGES); en.ts adds only the client's own keys. Every other
// locale translates the same set of keys, each a wire code or a client key.
func TestLocalesTranslateCatalogCodes(t *testing.T) {
	known := map[string]bool{}
	for _, c := range errmodel.Codes() {
		known[string(c)] = true
	}
	for _, c := range clientCodes {
		known[c] = true
	}
	keysOf := func(locale string) []string {
		src, err := os.ReadFile(filepath.Join(repo, "auth-ui/src/locales", locale+".ts"))
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
		return keys
	}
	en := keysOf("en")
	wantEN := slices.Sorted(slices.Values(clientCodes))
	if !slices.Equal(en, wantEN) {
		t.Errorf("en.ts error keys = %v, want only the client's own %v (English wire messages are generated)", en, wantEN)
	}
	var want []string
	for _, locale := range []string{"de", "es", "ja", "ko", "zh"} {
		keys := keysOf(locale)
		for _, k := range keys {
			if !known[k] {
				t.Errorf("%s: errors.%s is not an AuthKit wire code", locale, k)
			}
		}
		if want == nil {
			want = keys
		} else if !slices.Equal(keys, want) {
			t.Errorf("%s error keys differ from de:\n got %v\nwant %v", locale, keys, want)
		}
	}
}
