package authkit_test

import (
	"os"
	"regexp"
	"strings"
	"testing"

	"github.com/open-rails/authkit/internal/apisurface"
	"github.com/open-rails/authkit/internal/ident"
	rbacschema "github.com/open-rails/authkit/internal/rbac"
	"github.com/stretchr/testify/require"
)

// TestDocsRBACBuiltins keeps docs/rbac.md's built-in permission table equal to
// what AuthKit registers.
func TestDocsRBACBuiltins(t *testing.T) {
	doc, err := os.ReadFile("docs/rbac.md")
	require.NoError(t, err)
	_, table, ok := strings.Cut(string(doc), "\n| Built-in |")
	require.True(t, ok, "docs/rbac.md has no built-in permission table")
	table, _, _ = strings.Cut(table, "\n\n")
	row := regexp.MustCompile("(?m)^\\| `([^`]+)` \\|")
	var listed []string
	for _, m := range row.FindAllStringSubmatch(table, -1) {
		listed = append(listed, strings.ReplaceAll(m[1], "<persona>", "channel"))
	}
	registered := append(rbacschema.Builtins(ident.Persona("channel"), true), ident.IntrinsicRootPermissions()...)
	require.ElementsMatch(t, ident.Strings(registered), listed, "docs/rbac.md's built-in table must list exactly what AuthKit registers")
}

// TestDocsStabilityPackages keeps docs/stability.md's package table equal to
// the packages api/go.txt covers.
func TestDocsStabilityPackages(t *testing.T) {
	doc, err := os.ReadFile("docs/stability.md")
	require.NoError(t, err)
	_, table, ok := strings.Cut(string(doc), "\n| Package |")
	require.True(t, ok, "docs/stability.md has no package table")
	table, _, _ = strings.Cut(table, "\n\n")
	name := regexp.MustCompile("`([a-z/]+)`")
	var listed []string
	for line := range strings.Lines(table) {
		cells := strings.Split(line, "|")
		if len(cells) < 3 {
			continue
		}
		for _, m := range name.FindAllStringSubmatch(cells[1], -1) {
			listed = append(listed, strings.TrimPrefix(strings.TrimPrefix(m[1], "authkit"), "/"))
		}
	}
	require.ElementsMatch(t, apisurface.Packages, listed, "docs/stability.md's package table must list exactly the covered packages")
}
