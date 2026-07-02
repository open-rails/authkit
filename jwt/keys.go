package jwtkit

import (
	"crypto"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const (
	// DefaultAuthKeysPath is the default directory where External Secrets mounts auth keys
	DefaultAuthKeysPath = "/vault/auth"

	// DefaultKeyReloadInterval is how often a ReloadableKeySource re-stats
	// keys.json for changes. Short keeps the post-rotation multi-replica skew
	// window small; the cost is one stat() per tick. See authkit #90.
	DefaultKeyReloadInterval = 10 * time.Second
)

// KeySource provides the active signer and public keys for JWKS.
type KeySource interface {
	ActiveSigner() Signer
	PublicKeys() map[string]crypto.PublicKey
}

// StaticKeySource is a simple in-memory implementation.
type StaticKeySource struct {
	Active Signer
	Pubs   map[string]crypto.PublicKey
}

func (s StaticKeySource) ActiveSigner() Signer                    { return s.Active }
func (s StaticKeySource) PublicKeys() map[string]crypto.PublicKey { return clonePublicKeyMap(s.Pubs) }

// ReloadableKeySource wraps a file-backed StaticKeySource and hot-reloads it
// when keys.json changes on disk (e.g. re-rendered by Vault Agent), so signing-
// key rotation never requires a process restart. It implements KeySource; reads
// are lock-free via an atomic pointer. A background poller re-stats keys.json at
// the configured interval and, on change, atomically swaps in a NEW validated
// keystore. A malformed/unreadable file keeps the last-good keystore — a bad
// render never bricks signing. See authkit #90 (AK-IMPL-3).
type ReloadableKeySource struct {
	path     string // directory containing keys.json
	interval time.Duration
	cur      atomic.Pointer[StaticKeySource]

	mu      sync.Mutex // serializes Reload and guards lastMod
	lastMod time.Time

	done chan struct{}
	once sync.Once
}

// NewReloadableFileKeySource loads keys.json from the given directory and starts
// a background poller that hot-reloads it every interval (<=0 →
// DefaultKeyReloadInterval). It errors when no valid keys.json is present, so
// use it only where a file source is expected — env/dev sources don't reload
// (env is immutable in a running process; generated keys are dev-only).
func NewReloadableFileKeySource(path string, interval time.Duration) (*ReloadableKeySource, error) {
	if strings.TrimSpace(path) == "" {
		path = DefaultAuthKeysPath
	}
	if interval <= 0 {
		interval = DefaultKeyReloadInterval
	}
	static, err := loadStaticFromFile(path)
	if err != nil {
		return nil, err
	}
	r := &ReloadableKeySource{path: path, interval: interval, done: make(chan struct{})}
	r.cur.Store(static)
	if mod, modErr := r.keyFileModTime(); modErr == nil {
		r.lastMod = mod
	}
	go r.pollLoop()
	return r, nil
}

func (r *ReloadableKeySource) ActiveSigner() Signer { return r.cur.Load().ActiveSigner() }
func (r *ReloadableKeySource) PublicKeys() map[string]crypto.PublicKey {
	return r.cur.Load().PublicKeys()
}

func (r *ReloadableKeySource) keyFilePath() string { return filepath.Join(r.path, "keys.json") }

func (r *ReloadableKeySource) keyFileModTime() (time.Time, error) {
	fi, err := os.Stat(r.keyFilePath())
	if err != nil {
		return time.Time{}, err
	}
	return fi.ModTime(), nil
}

// Reload re-reads keys.json, validates it, and atomically swaps it in. On any
// read/parse/validation failure it KEEPS the current keystore and returns the
// error — it never serves a partial or empty key set.
func (r *ReloadableKeySource) Reload() error {
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
func (r *ReloadableKeySource) Close() { r.once.Do(func() { close(r.done) }) }

func (r *ReloadableKeySource) pollLoop() {
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
			if err := r.Reload(); err != nil {
				logf("Warning: keys.json reload failed, keeping current signing keys: %v", err)
				continue
			}
			r.mu.Lock()
			r.lastMod = mod
			r.mu.Unlock()
			logf("authkit: reloaded signing keys from %s (rotated active kid into service)", r.keyFilePath())
		}
	}
}

// loadStaticFromFile loads keys.json under path and asserts the concrete
// StaticKeySource shape that tryLoadFromFilesystem returns. It errors when no
// keys.json is present (unlike tryLoadFromFilesystem, which returns (nil,nil)),
// because the reloadable source requires a real file to back it.
func loadStaticFromFile(path string) (*StaticKeySource, error) {
	ks, err := tryLoadFromFilesystem(path)
	if err != nil {
		return nil, err
	}
	if ks == nil {
		return nil, fmt.Errorf("no keys.json found under %s", path)
	}
	static, ok := ks.(StaticKeySource)
	if !ok {
		return nil, fmt.Errorf("unexpected key source type %T from %s", ks, path)
	}
	if static.Active == nil {
		return nil, fmt.Errorf("keys.json under %s has no active signer", path)
	}
	return &static, nil
}

// GeneratedKeySource generates and persists RSA keys (for development only).
type GeneratedKeySource struct {
	signer *RSASigner
	pubs   map[string]crypto.PublicKey
}

const (
	// DefaultGeneratedKeysDir is the default directory under which the
	// development GeneratedKeySource persists its auto-generated keypair.
	DefaultGeneratedKeysDir = ".runtime/authkit"
	privateKeyFile          = "private.pem"
	keyIDFile               = "kid"
)

// NewGeneratedKeySource creates a KeySource with auto-generated RSA keys,
// persisting them under DefaultGeneratedKeysDir (".runtime/authkit"). For a
// custom directory use NewGeneratedKeySourceInDir.
func NewGeneratedKeySource() (*GeneratedKeySource, error) {
	return NewGeneratedKeySourceInDir(DefaultGeneratedKeysDir)
}

// NewGeneratedKeySourceInDir creates a KeySource with auto-generated RSA keys,
// loading from / persisting to the given directory. An empty dir defaults to
// DefaultGeneratedKeysDir. Development only.
func NewGeneratedKeySourceInDir(dir string) (*GeneratedKeySource, error) {
	if strings.TrimSpace(dir) == "" {
		dir = DefaultGeneratedKeysDir
	}
	if signer, pubs, ok := loadKeysFromDisk(dir); ok {
		return &GeneratedKeySource{signer: signer, pubs: pubs}, nil
	}

	kid := fmt.Sprintf("dev-%d", time.Now().Unix())
	signer, err := NewRSASigner(2048, kid)
	if err != nil {
		return nil, fmt.Errorf("failed to generate RSA key: %w", err)
	}

	if err := persistKeysToDisk(dir, signer, kid); err != nil {
		logf("Warning: failed to persist authkit dev keys: %v", err)
	}

	return &GeneratedKeySource{
		signer: signer,
		pubs:   map[string]crypto.PublicKey{kid: signer.PublicKey()},
	}, nil
}

func (g *GeneratedKeySource) ActiveSigner() Signer { return g.signer }
func (g *GeneratedKeySource) PublicKeys() map[string]crypto.PublicKey {
	return clonePublicKeyMap(g.pubs)
}

func loadKeysFromDisk(dir string) (*RSASigner, map[string]crypto.PublicKey, bool) {
	pemBytes, err := readFileUnderDir(dir, privateKeyFile)
	if err != nil {
		return nil, nil, false
	}

	kid := "dev"
	if kidBytes, err := readFileUnderDir(dir, keyIDFile); err == nil {
		if k := strings.TrimSpace(string(kidBytes)); k != "" {
			kid = k
		}
	}

	signer, err := NewRSASignerFromPEM(kid, pemBytes)
	if err != nil {
		return nil, nil, false
	}

	pubs := map[string]crypto.PublicKey{kid: signer.PublicKey()}
	return signer, pubs, true
}

func persistKeysToDisk(dir string, signer *RSASigner, kid string) error {
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("create keys directory: %w", err)
	}

	privDER := x509MarshalPKCS1PrivateKey(signer.PrivateKey())
	privPEM := pemEncode("RSA PRIVATE KEY", privDER)

	keyPath := filepath.Join(dir, privateKeyFile)
	if err := os.WriteFile(keyPath, privPEM, 0600); err != nil {
		return fmt.Errorf("write private key: %w", err)
	}

	kidPath := filepath.Join(dir, keyIDFile)
	if err := os.WriteFile(kidPath, []byte(kid), 0600); err != nil {
		return fmt.Errorf("write key ID: %w", err)
	}
	return nil
}

// envKeySource loads the active signing key and JWKS public keys from
// environment variables: ACTIVE_KEY_ID, ACTIVE_PRIVATE_KEY_PEM, and the
// optional PUBLIC_KEYS map (JSON of kid -> PEM). It returns (nil, nil) when no
// key env vars are set so it can compose as the first step of a resolver.
func envKeySource() (KeySource, error) {
	return tryLoadFromEnv()
}

// fileKeySource loads the active signing key and JWKS public keys from a
// keys.json file located under the given directory (default /vault/auth when
// path is empty). The file uses the {active_key_id, active_private_key_pem,
// public_keys} envelope. It returns (nil, nil) when the directory or keys.json
// does not exist so it can compose as a fallthrough step of a resolver.
func fileKeySource(path string) (KeySource, error) {
	return tryLoadFromFilesystem(path)
}

// newAutoKeySource auto-discovers JWT keys from multiple sources with the
// following priority (using the default filesystem path /vault/auth):
// 1. Environment variables (ACTIVE_KEY_ID, ACTIVE_PRIVATE_KEY_PEM, PUBLIC_KEYS)
// 2. Filesystem /vault/auth/keys.json
// 3. Auto-generated keys in .runtime/authkit/ (development fallback; prod hard-fail)
func newAutoKeySource() (KeySource, error) {
	return NewAutoKeySourceWithPath(DefaultAuthKeysPath)
}

// NewAutoKeySourceWithPath is newAutoKeySource with a host-overridable
// filesystem directory for the keys.json file. An empty path defaults to
// DefaultAuthKeysPath ("/vault/auth"). Precedence and the production hard-fail
// are identical to newAutoKeySource: env -> fileKeySource(path) ->
// GeneratedKeySource (non-prod only).
func NewAutoKeySourceWithPath(path string) (KeySource, error) {
	if strings.TrimSpace(path) == "" {
		path = DefaultAuthKeysPath
	}

	if keySource, err := envKeySource(); err != nil {
		return nil, fmt.Errorf("failed to load keys from environment variables: %w", err)
	} else if keySource != nil {
		return keySource, nil
	}

	// File branch: when keys.json exists, serve it through a ReloadableKeySource
	// so signing-key rotation (Vault Agent re-renders the file) takes effect
	// without a process restart. Falls through to the dev generator only when no
	// keys.json is present. The poller lives for the process lifetime; callers
	// needing lifecycle control use NewReloadableFileKeySource directly.
	if _, statErr := os.Stat(filepath.Join(path, "keys.json")); statErr == nil {
		rks, err := NewReloadableFileKeySource(path, DefaultKeyReloadInterval)
		if err != nil {
			return nil, fmt.Errorf("failed to load keys from %s: %w", path, err)
		}
		return rks, nil
	}

	if isProdEnv() {
		return nil, fmt.Errorf("no JWT keys found in env or %s and auto-generation is disabled in production; set ACTIVE_KEY_ID/ACTIVE_PRIVATE_KEY_PEM or mount keys.json", path)
	}

	keySource, err := NewGeneratedKeySource()
	if err != nil {
		return nil, fmt.Errorf("failed to generate development keys: %w", err)
	}
	return keySource, nil
}

func isProdEnv() bool {
	env := strings.TrimSpace(os.Getenv("ENV"))
	if env == "" {
		env = strings.TrimSpace(os.Getenv("APP_ENV"))
	}
	if env == "" {
		env = strings.TrimSpace(os.Getenv("ENVIRONMENT"))
	}
	env = strings.ToLower(env)
	return env == "production" || env == "prod"
}

func tryLoadFromEnv() (KeySource, error) {
	activeKeyID := strings.TrimSpace(os.Getenv("ACTIVE_KEY_ID"))
	activePrivateKeyPEM := strings.TrimSpace(os.Getenv("ACTIVE_PRIVATE_KEY_PEM"))

	if activeKeyID == "" && activePrivateKeyPEM == "" {
		return nil, nil
	}
	if activeKeyID == "" {
		return nil, fmt.Errorf("ACTIVE_PRIVATE_KEY_PEM is set but ACTIVE_KEY_ID is missing")
	}
	if activePrivateKeyPEM == "" {
		return nil, fmt.Errorf("ACTIVE_KEY_ID is set but ACTIVE_PRIVATE_KEY_PEM is missing")
	}

	signer, err := NewSignerFromPEM(activeKeyID, []byte(activePrivateKeyPEM))
	if err != nil {
		return nil, fmt.Errorf("failed to parse ACTIVE_PRIVATE_KEY_PEM: %w", err)
	}

	publicKeys := map[string]crypto.PublicKey{activeKeyID: signerPublicKey(signer)}

	publicKeysJSON := strings.TrimSpace(os.Getenv("PUBLIC_KEYS"))
	if publicKeysJSON != "" {
		var pubKeyMap map[string]string
		if err := json.Unmarshal([]byte(publicKeysJSON), &pubKeyMap); err != nil {
			return nil, fmt.Errorf("failed to parse PUBLIC_KEYS JSON: %w", err)
		}
		for kid, pemStr := range pubKeyMap {
			pub, err := ParsePublicKeyFromPEM(pemStr)
			if err != nil {
				logf("Warning: failed to parse public key %s from PUBLIC_KEYS: %v", kid, err)
				continue
			}
			publicKeys[kid] = pub
		}
	}

	return StaticKeySource{Active: signer, Pubs: publicKeys}, nil
}

func tryLoadFromFilesystem(keysPath string) (KeySource, error) {
	if keysPath == "" {
		keysPath = DefaultAuthKeysPath
	}

	if _, err := os.Stat(keysPath); os.IsNotExist(err) {
		return nil, nil
	}

	data, err := readFileUnderDir(keysPath, "keys.json")
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("failed to read keys.json: %w", err)
	}

	var keyData struct {
		ActiveKeyID         string            `json:"active_key_id"`
		ActivePrivateKeyPEM string            `json:"active_private_key_pem"`
		PublicKeys          map[string]string `json:"public_keys"`
	}
	if err := json.Unmarshal(data, &keyData); err != nil {
		return nil, fmt.Errorf("failed to parse keys.json: %w", err)
	}

	if keyData.ActiveKeyID == "" {
		return nil, fmt.Errorf("keys.json missing active_key_id")
	}
	if keyData.ActivePrivateKeyPEM == "" {
		return nil, fmt.Errorf("keys.json missing active_private_key_pem")
	}

	signer, err := NewSignerFromPEM(keyData.ActiveKeyID, []byte(keyData.ActivePrivateKeyPEM))
	if err != nil {
		return nil, fmt.Errorf("failed to parse private key: %w", err)
	}

	publicKeys := map[string]crypto.PublicKey{keyData.ActiveKeyID: signerPublicKey(signer)}
	for kid, pemStr := range keyData.PublicKeys {
		pub, err := ParsePublicKeyFromPEM(pemStr)
		if err != nil {
			logf("Warning: failed to parse public key %s: %v", kid, err)
			continue
		}
		publicKeys[kid] = pub
	}

	return StaticKeySource{Active: signer, Pubs: publicKeys}, nil
}

func signerPublicKey(s Signer) crypto.PublicKey {
	if ps, ok := s.(PublicKeySigner); ok {
		return ps.PublicKey()
	}
	return nil
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
