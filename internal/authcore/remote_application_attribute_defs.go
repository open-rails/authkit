package authcore

import (
	"context"
	"encoding/json"
	"errors"
	"strings"

	"github.com/jackc/pgx/v5"

	authkit "github.com/open-rails/authkit"
	"github.com/open-rails/authkit/internal/db"
)

var (
	// ErrAttributeDefNotFound is defined in authkit (core-free) and re-exported here.
	ErrAttributeDefNotFound = authkit.ErrAttributeDefNotFound
	// ErrInvalidAttributeDef indicates a malformed definition registration.
	ErrInvalidAttributeDef = authkit.ErrInvalidAttributeDef
)

// RemoteAppAttributeDef is one REFERENCE-mode attribute definition (#75): a
// remote_application registers (key, version) -> definition, and a platform
// resolves a token's `attributes.<key>: "<ref>"` reference back to it. The
// Definition is an OPAQUE JSON doc — AuthKit stores and serves it but NEVER
// interprets its semantics (same agnosticism as the token attributes bag).
// RemoteAppAttributeDef is defined in authkit (core-free) and re-exported here.
type RemoteAppAttributeDef = authkit.RemoteAppAttributeDef

// RegisterRemoteAppAttributeDef stores (or updates) a definition for the
// remote_application. version defaults to 1 when zero. The caller authority is
// the remote_application itself (it owns its users' restrictions); the http
// layer enforces that.
func (s *Service) RegisterRemoteAppAttributeDef(ctx context.Context, appID, key string, version int32, definition json.RawMessage) (*RemoteAppAttributeDef, error) {
	if err := s.requirePG(); err != nil {
		return nil, err
	}
	appID = strings.TrimSpace(appID)
	key = strings.TrimSpace(key)
	if appID == "" || key == "" {
		return nil, ErrInvalidAttributeDef
	}
	if version <= 0 {
		version = 1
	}
	if len(definition) == 0 || !json.Valid(definition) {
		return nil, ErrInvalidAttributeDef
	}
	row, err := s.q.RemoteAppAttributeDefUpsert(ctx, db.RemoteAppAttributeDefUpsertParams{
		RemoteApplicationID: appID,
		Key:                 key,
		Version:             version,
		Definition:          definition,
	})
	if err != nil {
		return nil, err
	}
	return &RemoteAppAttributeDef{RemoteApplicationID: row.RemoteApplicationID, Key: row.Key, Version: row.Version, Definition: row.Definition}, nil
}

// ResolveRemoteAppAttributeDef returns the definition for (appID, key, version).
// version <= 0 resolves the LATEST version. The returned Definition is opaque.
func (s *Service) ResolveRemoteAppAttributeDef(ctx context.Context, appID, key string, version int32) (*RemoteAppAttributeDef, error) {
	if err := s.requirePG(); err != nil {
		return nil, err
	}
	appID = strings.TrimSpace(appID)
	key = strings.TrimSpace(key)
	if appID == "" || key == "" {
		return nil, ErrInvalidAttributeDef
	}
	if version > 0 {
		row, err := s.q.RemoteAppAttributeDefGet(ctx, db.RemoteAppAttributeDefGetParams{RemoteApplicationID: appID, Key: key, Version: version})
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrAttributeDefNotFound
		}
		if err != nil {
			return nil, err
		}
		return &RemoteAppAttributeDef{RemoteApplicationID: row.RemoteApplicationID, Key: row.Key, Version: row.Version, Definition: row.Definition}, nil
	}
	row, err := s.q.RemoteAppAttributeDefGetLatest(ctx, db.RemoteAppAttributeDefGetLatestParams{RemoteApplicationID: appID, Key: key})
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrAttributeDefNotFound
	}
	if err != nil {
		return nil, err
	}
	return &RemoteAppAttributeDef{RemoteApplicationID: row.RemoteApplicationID, Key: row.Key, Version: row.Version, Definition: row.Definition}, nil
}
