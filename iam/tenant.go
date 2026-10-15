package iam

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"
)

var (
	ErrTenantRequired = errors.New("authkit: a tenant must be selected")
	ErrTenantNotFound = errors.New("authkit: tenant not found")
	ErrTenantMismatch = errors.New("authkit: tenant does not own this account or resource")
)

// TenantID is the canonical business identity, shared with ContentKit. It is
// not a schema name, application ID, issuer, or billing merchant ID.
type TenantID [16]byte

func NewTenantID() TenantID {
	var id TenantID
	if _, err := rand.Read(id[:]); err != nil {
		panic(fmt.Errorf("authkit: tenant entropy: %w", err))
	}
	id[6] = (id[6] & 0x0f) | 0x40
	id[8] = (id[8] & 0x3f) | 0x80
	return id
}

func ParseTenantID(text string) (TenantID, error) {
	var id TenantID
	text = strings.TrimSpace(text)
	switch len(text) {
	case 45:
		if !strings.EqualFold(text[:9], "urn:uuid:") {
			return id, fmt.Errorf("authkit: tenant ID must be a nonzero UUID")
		}
		text = text[9:]
	case 38:
		if text[0] != '{' || text[37] != '}' {
			return id, fmt.Errorf("authkit: tenant ID must be a nonzero UUID")
		}
		text = text[1:37]
	}
	if len(text) == 36 {
		if text[8] != '-' || text[13] != '-' || text[18] != '-' || text[23] != '-' {
			return id, fmt.Errorf("authkit: tenant ID must be a nonzero UUID")
		}
		text = text[:8] + text[9:13] + text[14:18] + text[19:23] + text[24:]
	}
	if len(text) != 32 {
		return id, fmt.Errorf("authkit: tenant ID must be a nonzero UUID")
	}
	if _, err := hex.Decode(id[:], []byte(text)); err != nil || id.IsZero() {
		return TenantID{}, fmt.Errorf("authkit: tenant ID must be a nonzero UUID")
	}
	return id, nil
}

func (id TenantID) IsZero() bool { return id == TenantID{} }
func (id TenantID) String() string {
	if id.IsZero() {
		return ""
	}
	text := hex.EncodeToString(id[:])
	return text[:8] + "-" + text[8:12] + "-" + text[12:16] + "-" + text[16:20] + "-" + text[20:]
}
func (id TenantID) MarshalText() ([]byte, error) { return []byte(id.String()), nil }
func (id *TenantID) UnmarshalText(text []byte) error {
	if len(text) == 0 {
		*id = TenantID{}
		return nil
	}
	parsed, err := ParseTenantID(string(text))
	if err != nil {
		return err
	}
	*id = parsed
	return nil
}

// Tenant is one independently registered business account directory. Its ID
// is supplied by trusted provisioning and never changes with a display name.
type Tenant struct {
	ID        TenantID  `json:"id"`
	CreatedAt time.Time `json:"created_at"`
}

// TenantActor identifies the live source account of a verified actor. It does
// not grant access to a target tenant or create an audience account there.
type TenantActor struct {
	AccountID string   `json:"account_id"`
	TenantID  TenantID `json:"tenant_id"`
}
