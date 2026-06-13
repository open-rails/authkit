package jwtkit

import (
	"crypto"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const (
	// DefaultAuthKeysPath is the default directory where External Secrets mounts auth keys
	DefaultAuthKeysPath = "/vault/auth"
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

// EnvKeySource loads the active signing key and JWKS public keys from
// environment variables: ACTIVE_KEY_ID, ACTIVE_PRIVATE_KEY_PEM, and the
// optional PUBLIC_KEYS map (JSON of kid -> PEM). It returns (nil, nil) when no
// key env vars are set so it can compose as the first step of a resolver.
func EnvKeySource() (KeySource, error) {
	return tryLoadFromEnv()
}

// FileKeySource loads the active signing key and JWKS public keys from a
// keys.json file located under the given directory (default /vault/auth when
// path is empty). The file uses the {active_key_id, active_private_key_pem,
// public_keys} envelope. It returns (nil, nil) when the directory or keys.json
// does not exist so it can compose as a fallthrough step of a resolver.
func FileKeySource(path string) (KeySource, error) {
	return tryLoadFromFilesystem(path)
}

// NewAutoKeySource auto-discovers JWT keys from multiple sources with the
// following priority (using the default filesystem path /vault/auth):
// 1. Environment variables (ACTIVE_KEY_ID, ACTIVE_PRIVATE_KEY_PEM, PUBLIC_KEYS)
// 2. Filesystem /vault/auth/keys.json
// 3. Auto-generated keys in .runtime/authkit/ (development fallback; prod hard-fail)
func NewAutoKeySource() (KeySource, error) {
	return NewAutoKeySourceWithPath(DefaultAuthKeysPath)
}

// NewAutoKeySourceWithPath is NewAutoKeySource with a host-overridable
// filesystem directory for the keys.json file. An empty path defaults to
// DefaultAuthKeysPath ("/vault/auth"). Precedence and the production hard-fail
// are identical to NewAutoKeySource: env -> FileKeySource(path) ->
// GeneratedKeySource (non-prod only).
func NewAutoKeySourceWithPath(path string) (KeySource, error) {
	if strings.TrimSpace(path) == "" {
		path = DefaultAuthKeysPath
	}

	if keySource, err := EnvKeySource(); err != nil {
		return nil, fmt.Errorf("failed to load keys from environment variables: %w", err)
	} else if keySource != nil {
		return keySource, nil
	}

	if keySource, err := FileKeySource(path); err != nil {
		return nil, fmt.Errorf("failed to load keys from %s: %w", path, err)
	} else if keySource != nil {
		return keySource, nil
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
