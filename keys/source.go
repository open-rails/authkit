package keys

import (
	"crypto"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// defaultKeyReloadInterval is how often a FileSource re-stats keys.json:
// short keeps the post-rotation multi-replica skew small (authkit #90).
const defaultKeyReloadInterval = 10 * time.Second

// Source is a deployment's signing keys: the active signer, and the public
// keys its JWKS publishes (the active one and retired ones still verifying).
type Source interface {
	ActiveSigner() Signer
	PublicKeys() map[string]crypto.PublicKey
}

// Static is a fixed Source.
type Static struct {
	// Active signs.
	Active Signer
	// Public is every key JWKS publishes, the active one included, by kid.
	Public map[string]crypto.PublicKey
}

func (s Static) ActiveSigner() Signer                    { return s.Active }
func (s Static) PublicKeys() map[string]crypto.PublicKey { return clonePublicKeyMap(s.Public) }

// FileSource is the Source Watch returns: keys.json, reloaded when it changes
// on disk (re-rendered by Vault Agent), so a signing-key rotation needs no
// restart. Reads are lock-free. A malformed or unreadable file keeps the last
// good keys: a bad render never bricks signing (authkit #90).
type FileSource struct {
	path     string // directory containing keys.json
	interval time.Duration
	log      *slog.Logger
	cur      atomic.Pointer[Static]

	mu      sync.Mutex // serializes Reload and guards lastMod
	lastMod time.Time

	done chan struct{}
	once sync.Once
}

// Watch loads <path>/keys.json, the envelope {active_key_id,
// active_private_key_pem, public_keys: {kid: pem}}, and re-reads it every
// 10s when it changed. It errors when path holds no valid keys.json. Close
// stops the watch; reloads are logged on slog.Default.
func Watch(path string) (*FileSource, error) {
	return watch(path, defaultKeyReloadInterval, slog.Default())
}

func watch(path string, interval time.Duration, log *slog.Logger) (*FileSource, error) {
	if strings.TrimSpace(path) == "" {
		return nil, fmt.Errorf("key directory required")
	}
	static, err := loadStaticFromFile(path)
	if err != nil {
		return nil, err
	}
	r := &FileSource{path: path, interval: interval, log: log, done: make(chan struct{})}
	r.cur.Store(static)
	if mod, modErr := r.keyFileModTime(); modErr == nil {
		r.lastMod = mod
	}
	go r.pollLoop()
	return r, nil
}

func (r *FileSource) ActiveSigner() Signer { return r.cur.Load().ActiveSigner() }
func (r *FileSource) PublicKeys() map[string]crypto.PublicKey {
	return r.cur.Load().PublicKeys()
}

func (r *FileSource) keyFilePath() string { return filepath.Join(r.path, "keys.json") }

func (r *FileSource) keyFileModTime() (time.Time, error) {
	fi, err := os.Stat(r.keyFilePath())
	if err != nil {
		return time.Time{}, err
	}
	return fi.ModTime(), nil
}

// Reload re-reads keys.json, validates it, and atomically swaps it in. On any
// read/parse/validation failure it KEEPS the current keystore and returns the
// error — it never serves a partial or empty key set.
func (r *FileSource) Reload() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	static, err := loadStaticFromFile(r.path)
	if err != nil {
		return err
	}
	r.cur.Store(static)
	return nil
}

// Close stops the background poller. Safe to call multiple times; optional for
// process-lifetime sources (primarily for tests and clean shutdown).
func (r *FileSource) Close() { r.once.Do(func() { close(r.done) }) }

func (r *FileSource) pollLoop() {
	ticker := time.NewTicker(r.interval)
	defer ticker.Stop()
	for {
		select {
		case <-r.done:
			return
		case <-ticker.C:
			mod, err := r.keyFileModTime()
			if err != nil {
				continue // transient (e.g. mid-render); keep current keys, retry next tick
			}
			r.mu.Lock()
			unchanged := !mod.After(r.lastMod)
			r.mu.Unlock()
			if unchanged {
				continue
			}
			prevKID := ""
			if prev := r.cur.Load(); prev != nil {
				prevKID = prev.ActiveSigner().KID()
			}
			if err := r.Reload(); err != nil {
				r.log.Warn("authkit: keys.json reload failed, keeping current signing keys", "path", r.keyFilePath(), "err", err)
				continue
			}
			r.mu.Lock()
			r.lastMod = mod
			r.mu.Unlock()
			// This log describes only what THIS source observed: the swap is a
			// single atomic pointer store, visible immediately to every reader
			// holding this Source. It makes no claim about which service/
			// process consumes it — that is the caller's responsibility (#238).
			newKID := r.cur.Load().ActiveSigner().KID()
			r.log.Info("authkit: reloaded signing keys", "path", r.keyFilePath(), "previous_kid", prevKID, "active_kid", newKID)
		}
	}
}

// loadStaticFromFile loads the keys.json envelope under path:
// {active_key_id, active_private_key_pem, public_keys: {kid: pem}}.
func loadStaticFromFile(path string) (*Static, error) {
	data, err := readFileUnderDir(path, "keys.json")
	if err != nil {
		return nil, fmt.Errorf("read keys.json under %s: %w", path, err)
	}
	var keyData struct {
		ActiveKeyID         string            `json:"active_key_id"`
		ActivePrivateKeyPEM string            `json:"active_private_key_pem"`
		PublicKeys          map[string]string `json:"public_keys"`
	}
	if err := json.Unmarshal(data, &keyData); err != nil {
		return nil, fmt.Errorf("failed to parse keys.json: %w", err)
	}
	ks, err := StaticFromPEM(keyData.ActiveKeyID, keyData.ActivePrivateKeyPEM, keyData.PublicKeys)
	if err != nil {
		return nil, err
	}
	return &ks, nil
}

// StaticFromPEM builds a Static source from the active signing key (kid and
// private-key PEM) plus verification-only public keys (kid to PEM, such as
// retired keys kept in the JWKS during rotation). It performs no I/O. An
// unparseable public key is an error: a verifier that silently drops a
// rotation key would reject every token it signed.
func StaticFromPEM(activeKeyID, activePrivateKeyPEM string, publicKeysPEM map[string]string) (Static, error) {
	activeKeyID = strings.TrimSpace(activeKeyID)
	activePrivateKeyPEM = strings.TrimSpace(activePrivateKeyPEM)
	if activeKeyID == "" {
		return Static{}, fmt.Errorf("active key ID is required")
	}
	if activePrivateKeyPEM == "" {
		return Static{}, fmt.Errorf("active private key PEM is required")
	}

	signer, err := SignerFromPEM(activeKeyID, []byte(activePrivateKeyPEM))
	if err != nil {
		return Static{}, fmt.Errorf("failed to parse private key: %w", err)
	}

	publicKeys := map[string]crypto.PublicKey{activeKeyID: signer.Public()}
	for kid, pemStr := range publicKeysPEM {
		pub, err := ParsePublicPEM([]byte(pemStr))
		if err != nil {
			return Static{}, fmt.Errorf("public key %q: %w", kid, err)
		}
		publicKeys[kid] = pub
	}

	return Static{Active: signer, Public: publicKeys}, nil
}

// readFileUnderDir reads a single path segment under baseDir, rejecting traversal.
func readFileUnderDir(baseDir, name string) ([]byte, error) {
	cleanName := filepath.Clean(name)
	if cleanName != name || cleanName == "." || cleanName == ".." || strings.Contains(cleanName, string(os.PathSeparator)) {
		return nil, fmt.Errorf("invalid file name %q", name)
	}
	root, err := os.OpenRoot(baseDir)
	if err != nil {
		return nil, err
	}
	defer root.Close()
	return root.ReadFile(cleanName)
}
