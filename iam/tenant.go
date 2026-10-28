package iam

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/open-rails/authkit/internal/errmodel"
)

var (
	ErrTenantRequired = errors.New("authkit: a tenant must be selected")
	ErrTenantNotFound = errors.New("authkit: tenant not found")
	ErrTenantMismatch = errors.New("authkit: tenant does not own this account or resource")
)

var (
	// ErrInvalidTenantSlug refuses a name ValidateTenantSlug rejects.
	ErrInvalidTenantSlug Error = errmodel.E(errmodel.CodeInvalidTenantSlug)
	// ErrTenantNameTaken refuses a name another tenant holds, now or as an
	// unexpired former name.
	ErrTenantNameTaken Error = errmodel.E(errmodel.CodeTenantNameTaken)
	// ErrTenantConflict refuses to create a tenant whose ID already has
	// another name.
	ErrTenantConflict Error = errmodel.E(errmodel.CodeTenantConflict)
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
// is supplied by trusted provisioning and never changes. Slug is its public
// name: renamable, so tokens, scopes, keys and storage paths use the ID.
type Tenant struct {
	ID            TenantID   `json:"id"`
	Slug          string     `json:"slug"`
	SlugChangedAt *time.Time `json:"slug_changed_at"`
	CreatedAt     time.Time  `json:"created_at"`
}

var tenantSlugRe = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$`)

// NormalizeTenantSlug is the stored form of a tenant name: trimmed and
// lowercased.
func NormalizeTenantSlug(s string) string { return strings.ToLower(strings.TrimSpace(s)) }

// ValidateTenantSlug reports whether the normalized s is a legal tenant name:
// lowercase a-z, 0-9 and hyphens, no leading or trailing hyphen, at most 63
// characters. Names a product reserves are the caller's policy.
func ValidateTenantSlug(s string) error {
	if !tenantSlugRe.MatchString(NormalizeTenantSlug(s)) {
		return ErrInvalidTenantSlug
	}
	return nil
}

// TenantActor identifies the live source account of a verified actor. It does
// not grant access to a target tenant or create an audience account there.
type TenantActor struct {
	AccountID string   `json:"account_id"`
	TenantID  TenantID `json:"tenant_id"`
}
