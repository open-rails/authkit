// Package rootsnapshot defines the bounded native-user root authority claim.
// It is shared by issuance and verification, not a public authorization API.
package rootsnapshot

import (
	"encoding/json"
	"errors"
	"regexp"
	"slices"
)

const (
	Claim     = "root_permissions"
	Version   = 1
	MaxGrants = 128
	MaxBytes  = 4096
)

var ErrInvalid = errors.New("authkit: invalid root permission snapshot")
var grantPattern = regexp.MustCompile(`^root:(\*|[a-z][a-z0-9-]*:(\*|[a-z][a-z0-9-]*))$`)
var concretePermission = regexp.MustCompile(`^root:[a-z][a-z0-9-]*:[a-z][a-z0-9-]*$`)
var canonicalUUID = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

type Value struct {
	Version  int      `json:"v"`
	Issuer   string   `json:"issuer"`
	GroupID  string   `json:"group_id"`
	Complete bool     `json:"complete"`
	Grants   []string `json:"grants"`
}

// New never truncates authority. An empty non-nil grant list is a complete
// negative; inability to represent all authority is an omitted snapshot.
func New(issuer, groupID string, grants []string) (*Value, error) {
	copy := append([]string{}, grants...)
	slices.Sort(copy)
	copy = slices.Compact(copy)
	v := &Value{Version: Version, Issuer: issuer, GroupID: groupID, Complete: true, Grants: copy}
	if err := v.validate(issuer); err != nil {
		return nil, err
	}
	raw, err := json.Marshal(v)
	if err != nil || len(raw) > MaxBytes {
		return nil, ErrInvalid
	}
	return v, nil
}

// Parse returns nil for an unsupported version or an explicitly incomplete
// snapshot. Malformed known-version claims never become partial authority.
func Parse(claim any, issuer string) (*Value, error) {
	raw, err := json.Marshal(claim)
	if err != nil || len(raw) > MaxBytes {
		return nil, ErrInvalid
	}
	var version struct {
		Version *int `json:"v"`
	}
	if err := json.Unmarshal(raw, &version); err != nil || version.Version == nil {
		return nil, ErrInvalid
	}
	if *version.Version != Version {
		return nil, nil
	}
	var value Value
	if err := json.Unmarshal(raw, &value); err != nil {
		return nil, ErrInvalid
	}
	if err := value.validate(issuer); err != nil {
		return nil, err
	}
	if !value.Complete {
		return nil, nil
	}
	return &value, nil
}

func (v *Value) validate(issuer string) error {
	if !canonicalUUID.MatchString(v.GroupID) || v.GroupID == "00000000-0000-0000-0000-000000000000" || issuer == "" || v.Issuer != issuer || v.Grants == nil || len(v.Grants) > MaxGrants {
		return ErrInvalid
	}
	seen := make(map[string]bool, len(v.Grants))
	for _, grant := range v.Grants {
		if !grantPattern.MatchString(grant) || seen[grant] {
			return ErrInvalid
		}
		seen[grant] = true
	}
	return nil
}

func Concrete(permission string) bool { return concretePermission.MatchString(permission) }
