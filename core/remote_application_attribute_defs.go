package core

import (
	"context"
	"encoding/json"
	"errors"
	"strings"

	"github.com/jackc/pgx/v5"

	"github.com/open-rails/authkit/internal/db"
)

var (
	// ErrAttributeDefNotFound indicates no registered definition matched.
	ErrAttributeDefNotFound = errors.New("attribute_def_not_found")
	// ErrInvalidAttributeDef indicates a malformed definition registration.
	ErrInvalidAttributeDef = errors.New("invalid_attribute_def")
)

// RemoteAppAttributeDef is one REFERENCE-mode attribute definition (#75): a
// remote_application registers (key, version) -> definition, and a platform
// resolves a token's `attributes.<key>: "<ref>"` reference back to it. The
// Definition is an OPAQUE JSON doc — AuthKit stores and serves it but NEVER
// interprets its semantics (same agnosticism as the token attributes bag).
type RemoteAppAttributeDef struct {
	RemoteApplicationID string
	Key                 string
	Version             int32
	Definition          json.RawMessage
}

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

// ListRemoteAppAttributeDefs returns all definitions a remote_application has
// registered (every key + version), newest version first within each key.
func (s *Service) ListRemoteAppAttributeDefs(ctx context.Context, appID string) ([]RemoteAppAttributeDef, error) {
	if err := s.requirePG(); err != nil {
		return nil, err
	}
	appID = strings.TrimSpace(appID)
	if appID == "" {
		return nil, ErrInvalidAttributeDef
	}
	rows, err := s.q.RemoteAppAttributeDefsList(ctx, appID)
	if err != nil {
		return nil, err
	}
	out := make([]RemoteAppAttributeDef, 0, len(rows))
	for _, r := range rows {
		out = append(out, RemoteAppAttributeDef{RemoteApplicationID: r.RemoteApplicationID, Key: r.Key, Version: r.Version, Definition: r.Definition})
	}
	return out, nil
}

// DeleteRemoteAppAttributeDef removes ALL versions of a key for the
// remote_application. Returns ErrAttributeDefNotFound when nothing matched.
func (s *Service) DeleteRemoteAppAttributeDef(ctx context.Context, appID, key string) error {
	if err := s.requirePG(); err != nil {
		return err
	}
	appID = strings.TrimSpace(appID)
	key = strings.TrimSpace(key)
	if appID == "" || key == "" {
		return ErrInvalidAttributeDef
	}
	n, err := s.q.RemoteAppAttributeDefDelete(ctx, db.RemoteAppAttributeDefDeleteParams{RemoteApplicationID: appID, Key: key})
	if err != nil {
		return err
	}
	if n == 0 {
		return ErrAttributeDefNotFound
	}
	return nil
}
