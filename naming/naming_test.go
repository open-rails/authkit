package naming_test

import (
	"testing"
	"time"

	"github.com/open-rails/authkit/naming"
)

func TestPolicy(t *testing.T) {
	at := time.Date(2026, 11, 24, 12, 0, 0, 0, time.UTC)
	if got := naming.NextRename(at); !got.Equal(at.Add(72 * time.Hour)) {
		t.Fatalf("NextRename = %s", got)
	}
	if got := naming.FormerNameExpiry(at); !got.Equal(at.AddDate(0, 0, 90)) {
		t.Fatalf("FormerNameExpiry = %s", got)
	}
}
