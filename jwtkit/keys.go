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
// use it only where a file source is expected — static/dev sources don't reload
// (in-memory material is immutable in a running process; generated keys are
// dev-only).
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

// NewStaticKeySourceFromPEM builds a StaticKeySource from explicit key
// material: the active signing key (kid + private-key PEM) plus optional extra
// verification-only public keys (kid -> public-key PEM, e.g. retired keys kept
// in the JWKS during rotation). It performs no I/O and reads no environment
// variables — callers (binaries, hosts) own where the material comes from
// (#231). Unparseable extra public keys are skipped with a warning, matching
// the keys.json loader.
func NewStaticKeySourceFromPEM(activeKeyID, activePrivateKeyPEM string, publicKeysPEM map[string]string) (StaticKeySource, error) {
	activeKeyID = strings.TrimSpace(activeKeyID)
	activePrivateKeyPEM = strings.TrimSpace(activePrivateKeyPEM)
	if activeKeyID == "" {
		return StaticKeySource{}, fmt.Errorf("active key ID is required")
	}
	if activePrivateKeyPEM == "" {
		return StaticKeySource{}, fmt.Errorf("active private key PEM is required")
	}

	signer, err := NewSignerFromPEM(activeKeyID, []byte(activePrivateKeyPEM))
	if err != nil {
		return StaticKeySource{}, fmt.Errorf("failed to parse private key: %w", err)
	}

	publicKeys := map[string]crypto.PublicKey{activeKeyID: signerPublicKey(signer)}
	for kid, pemStr := range publicKeysPEM {
		pub, err := ParsePublicKeyFromPEM(pemStr)
		if err != nil {
			logf("Warning: failed to parse public key %s: %v", kid, err)
			continue
		}
		publicKeys[kid] = pub
	}

	return StaticKeySource{Active: signer, Pubs: publicKeys}, nil
}

// ResolveKeySource resolves the local signing-key source with a fixed,
// explicit precedence. It reads NO environment variables (#231 — AuthKit is a
// library; env is read once, at the binary boundary, and flows in as explicit
// arguments/config):
//
//  1. <path>/keys.json (path empty ⇒ DefaultAuthKeysPath "/vault/auth"),
//     served through a ReloadableKeySource so signing-key rotation (e.g. Vault
//     Agent re-rendering the file) takes effect without a process restart.
//  2. No keys.json: when allowEphemeralDevKeys is true, an auto-generated RSA
//     dev keypair persisted under .runtime/authkit/ (DEVELOPMENT ONLY);
//     when false — the default, fail-closed posture — a hard error.
//
// Callers that hold key material in memory should build a source directly
// (NewStaticKeySourceFromPEM / StaticKeySource) instead.
func ResolveKeySource(path string, allowEphemeralDevKeys bool) (KeySource, error) {
	if strings.TrimSpace(path) == "" {
		path = DefaultAuthKeysPath
	}

	if _, statErr := os.Stat(filepath.Join(path, "keys.json")); statErr == nil {
		rks, err := NewReloadableFileKeySource(path, DefaultKeyReloadInterval)
		if err != nil {
			return nil, fmt.Errorf("failed to load keys from %s: %w", path, err)
		}
		return rks, nil
	}

	if !allowEphemeralDevKeys {
		return nil, fmt.Errorf("no JWT signing keys: %s/keys.json not found and ephemeral dev keys are not enabled; mount keys.json, provide an explicit KeySource, or opt in with AllowEphemeralDevKeys for local development", path)
	}

	keySource, err := NewGeneratedKeySource()
	if err != nil {
		return nil, fmt.Errorf("failed to generate development keys: %w", err)
	}
	return keySource, nil
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

	ks, err := NewStaticKeySourceFromPEM(keyData.ActiveKeyID, keyData.ActivePrivateKeyPEM, keyData.PublicKeys)
	if err != nil {
		return nil, err
	}
	return ks, nil
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
