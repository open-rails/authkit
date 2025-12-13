package ginutil

import "testing"

func TestOriginFromBaseURL(t *testing.T) {
	t.Run("absolute_with_path", func(t *testing.T) {
		origin, ok := OriginFromBaseURL("https://example.com/foo/bar")
		if !ok {
			t.Fatalf("expected ok=true")
		}
		if origin != "https://example.com" {
			t.Fatalf("expected origin=https://example.com, got %q", origin)
		}
	})

	t.Run("absolute_no_path", func(t *testing.T) {
		origin, ok := OriginFromBaseURL("http://localhost:5173")
		if !ok {
			t.Fatalf("expected ok=true")
		}
		if origin != "http://localhost:5173" {
			t.Fatalf("expected origin=http://localhost:5173, got %q", origin)
		}
	})

	t.Run("relative_rejected", func(t *testing.T) {
		if _, ok := OriginFromBaseURL("/"); ok {
			t.Fatalf("expected ok=false")
		}
	})

	t.Run("missing_scheme_rejected", func(t *testing.T) {
		if _, ok := OriginFromBaseURL("example.com"); ok {
			t.Fatalf("expected ok=false")
		}
	})
}

