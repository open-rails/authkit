package engine

import (
	"bytes"
	"encoding/hex"
	"io/fs"
	stdlog "log"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

// Group-read (a Kubernetes secret volume with fsGroup) loads silently,
// world-read loads with a warning, and any write bit beyond the owner's is
// refused.
func TestLoadTOTPKeyPermissions(t *testing.T) {
	var logged bytes.Buffer
	stdlog.SetOutput(&logged)
	t.Cleanup(func() { stdlog.SetOutput(os.Stderr) })

	want := bytes.Repeat([]byte{7}, 32)
	for _, tc := range []struct {
		mode   fs.FileMode
		warns  bool
		refuse bool
	}{
		{mode: 0o600},
		{mode: 0o400},
		{mode: 0o440},
		{mode: 0o444, warns: true},
		{mode: 0o460, refuse: true},
		{mode: 0o602, refuse: true},
	} {
		logged.Reset()
		path := filepath.Join(t.TempDir(), totpKeyFilename)
		require.NoError(t, os.WriteFile(path, []byte(hex.EncodeToString(want)), 0o600))
		require.NoError(t, os.Chmod(path, tc.mode))

		key, err := loadTOTPKey(path)
		if tc.refuse {
			require.ErrorContains(t, err, "group/world-writable", "%#o", tc.mode)
			require.Nil(t, key)
			continue
		}
		require.NoError(t, err, "%#o", tc.mode)
		require.Equal(t, want, key)
		if tc.warns {
			require.Contains(t, logged.String(), "TOTP key "+path+" is world-readable", "%#o", tc.mode)
		} else {
			require.NotContains(t, logged.String(), "TOTP key", "%#o", tc.mode)
		}
	}
}
