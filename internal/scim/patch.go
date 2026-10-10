package scim

import (
	"encoding/json"
	"net/http"
	"strings"
)

// PatchRequest is a PATCH request (RFC 7644 §3.5.2).
type PatchRequest struct {
	Schemas    []string         `json:"schemas"`
	Operations []PatchOperation `json:"Operations"`
}

// PatchOperation is one operation: add, replace or remove at path, or at the
// resource itself when path is empty.
type PatchOperation struct {
	Op    string          `json:"op"`
	Path  string          `json:"path,omitempty"`
	Value json.RawMessage `json:"value,omitempty"`
}

// Apply applies the operations to u in order (RFC 7644 §3.5.2), all or
// none. The attributes a directory keeps are changed; any other attribute,
// another schema's included, is accepted and ignored as a create ignores it
// (RFC 7644 §3.3). A directory keeps one address, so every emails path
// addresses it; a value filter is matched against it (§3.5.2: an add whose
// filter matches nothing adds an address with the filter's type).
func (req PatchRequest) Apply(u *User) error {
	if !containsFold(req.Schemas, SchemaPatchOp) {
		return Fail(http.StatusBadRequest, "invalidSyntax", "schemas must name "+SchemaPatchOp)
	}
	if len(req.Operations) == 0 {
		return Fail(http.StatusBadRequest, "invalidSyntax", "Operations must list at least one operation")
	}
	next := *u
	next.Emails = append([]Email(nil), u.Emails...)
	if u.Name != nil {
		name := *u.Name
		next.Name = &name
	}
	for _, o := range req.Operations {
		op := strings.ToLower(strings.TrimSpace(o.Op))
		path := strings.TrimSpace(o.Path)
		switch {
		case op != "add" && op != "replace" && op != "remove":
			return Fail(http.StatusBadRequest, "invalidSyntax", `op must be "add", "replace" or "remove"`)
		case op == "remove" && path == "":
			return Fail(http.StatusBadRequest, "noTarget", "remove needs a path") // §3.5.2.2
		case op != "remove" && len(o.Value) == 0:
			return Fail(http.StatusBadRequest, "invalidValue", op+" needs a value") // §3.5.2.1, §3.5.2.3
		}
		if path != "" {
			if err := next.patch(op, path, o.Value); err != nil {
				return err
			}
			continue
		}
		var attrs map[string]json.RawMessage
		if json.Unmarshal(o.Value, &attrs) != nil {
			return Fail(http.StatusBadRequest, "invalidValue", "an operation without a path takes an object of attributes")
		}
		for name, value := range attrs {
			if err := next.patch(op, name, value); err != nil {
				return err
			}
		}
	}
	*u = next
	return nil
}

// attrPath is a parsed PATCH path: attr[filter].sub (RFC 7644 §3.5.2).
type attrPath struct {
	attr, filter, sub string
}

// parsePath parses path, attribute names lower-cased (RFC 7643 §2.1: they
// are case-insensitive). ok is false for another schema's attribute.
func parsePath(path string) (attrPath, bool, error) {
	invalid := Fail(http.StatusBadRequest, "invalidPath", "the path "+path+" is not one")
	if strings.HasPrefix(strings.ToLower(path), "urn:") {
		prefix := strings.ToLower(SchemaUser) + ":"
		if !strings.HasPrefix(strings.ToLower(path), prefix) {
			return attrPath{}, false, nil
		}
		path = path[len(prefix):]
	}
	var p attrPath
	rest := path
	if i := strings.IndexAny(rest, "[."); i >= 0 {
		p.attr, rest = rest[:i], rest[i:]
	} else {
		p.attr, rest = rest, ""
	}
	if strings.HasPrefix(rest, "[") {
		end := strings.Index(rest, "]")
		if end < 0 {
			return attrPath{}, false, invalid
		}
		p.filter, rest = strings.TrimSpace(rest[1:end]), rest[end+1:]
		if p.filter == "" {
			return attrPath{}, false, invalid
		}
	}
	if strings.HasPrefix(rest, ".") {
		p.sub, rest = rest[1:], ""
		if !attrName(p.sub) {
			return attrPath{}, false, invalid
		}
	}
	if rest != "" || !attrName(p.attr) {
		return attrPath{}, false, invalid
	}
	p.attr, p.sub = strings.ToLower(p.attr), strings.ToLower(p.sub)
	return p, true, nil
}

// attrName is RFC 7643 §2.1's ATTRNAME: ALPHA *(nameChar).
func attrName(s string) bool {
	for i, c := range s {
		alpha := c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z'
		if !alpha && (i == 0 || !(c >= '0' && c <= '9' || c == '-' || c == '_')) {
			return false
		}
	}
	return s != ""
}

func (u *User) patch(op, path string, value json.RawMessage) error {
	p, ours, err := parsePath(path)
	if err != nil || !ours {
		return err
	}
	remove := op == "remove"
	plain := func() error {
		if p.filter != "" || p.sub != "" {
			return Fail(http.StatusBadRequest, "invalidPath", p.attr+" has no sub-attributes")
		}
		return nil
	}
	switch p.attr {
	case "username", "externalid":
		if err := plain(); err != nil {
			return err
		}
		if remove {
			return Fail(http.StatusBadRequest, "invalidValue", path+" is required")
		}
		s, err := stringValue(path, value)
		if err != nil {
			return err
		}
		if p.attr == "username" {
			u.UserName = s
		} else {
			u.ExternalID = s
		}
	case "displayname":
		if err := plain(); err != nil {
			return err
		}
		if remove {
			u.DisplayName = ""
			return nil
		}
		s, err := stringValue(path, value)
		u.DisplayName = s
		return err
	case "name":
		return u.patchName(op, p, value)
	case "emails":
		return u.patchEmails(op, p, value)
	case "active":
		if err := plain(); err != nil {
			return err
		}
		if remove {
			u.Active = nil // unassigned: active by default
			return nil
		}
		b, err := boolValue(path, value)
		u.Active = &b
		return err
	case "id":
		if s, err := stringValue(path, value); remove || err != nil || s != u.ID {
			return Fail(http.StatusBadRequest, "mutability", "id is assigned by the service provider")
		}
	}
	// meta and schemas are the service provider's (RFC 7643 §3.1); an
	// attribute a directory does not keep changes nothing.
	return nil
}

func (u *User) patchName(op string, p attrPath, value json.RawMessage) error {
	if p.filter != "" {
		return Fail(http.StatusBadRequest, "invalidPath", "name is single-valued")
	}
	if u.Name == nil {
		u.Name = &Name{}
	}
	set := func(field *string, raw json.RawMessage) error {
		if op == "remove" {
			*field = ""
			return nil
		}
		s, err := stringValue("name."+p.sub, raw)
		*field = s
		return err
	}
	switch p.sub {
	case "":
		if op == "remove" {
			u.Name = nil
			return nil
		}
		// A complex attribute's add or replace sets the sub-attributes given
		// and leaves the others (§3.5.2.1, §3.5.2.3).
		var subs map[string]json.RawMessage
		if json.Unmarshal(value, &subs) != nil {
			return Fail(http.StatusBadRequest, "invalidValue", "name takes an object")
		}
		for name, raw := range subs {
			if err := u.patchName(op, attrPath{attr: "name", sub: strings.ToLower(name)}, raw); err != nil {
				return err
			}
		}
	case "formatted":
		return set(&u.Name.Formatted, value)
	case "givenname":
		return set(&u.Name.GivenName, value)
	case "familyname":
		return set(&u.Name.FamilyName, value)
	}
	return nil
}

func (u *User) patchEmails(op string, p attrPath, value json.RawMessage) error {
	held := primary(u.Emails)
	has := len(u.Emails) > 0
	if p.filter != "" {
		attr, want, err := valueFilter(p.filter)
		if err != nil {
			return err
		}
		if !has || !held.matches(attr, want) {
			switch op {
			case "remove":
				return nil
			case "replace":
				return Fail(http.StatusBadRequest, "noTarget", "no address matches "+p.filter) // §3.5.2.3
			}
			// add: a new address, typed as the filter selects it.
			held, has = Email{}, false
			if attr == "type" {
				held.Type = want
			}
		}
	}
	keep := func(e Email) {
		e.Primary = true
		u.Emails = []Email{e}
	}
	if op == "remove" {
		switch p.sub {
		case "", "value":
			u.Emails = nil
		case "type":
			if has {
				held.Type = ""
				keep(held)
			}
		}
		return nil
	}
	switch p.sub {
	case "":
		var list []Email
		if p.filter != "" || len(value) > 0 && value[0] == '{' {
			var e Email
			if json.Unmarshal(value, &e) != nil {
				return Fail(http.StatusBadRequest, "invalidValue", "an address is an object")
			}
			list = []Email{e}
		} else if json.Unmarshal(value, &list) != nil {
			return Fail(http.StatusBadRequest, "invalidValue", "emails takes a list of addresses")
		}
		next := primary(list)
		switch {
		case op == "add" && has && !hasPrimary(list):
			// An add appends (§3.5.2.1); the held address stays the kept one.
		case next.Value == "" && op == "replace" && p.filter == "":
			u.Emails = nil
		case next.Value != "":
			if next.Type == "" && p.filter != "" {
				next.Type = held.Type
			}
			keep(next)
		}
	case "value":
		s, err := stringValue("emails.value", value)
		if err != nil {
			return err
		}
		held.Value = s
		keep(held)
	case "type":
		s, err := stringValue("emails.type", value)
		if err != nil {
			return err
		}
		if has {
			held.Type = s
			keep(held)
		}
	}
	return nil
}

func hasPrimary(list []Email) bool {
	for _, e := range list {
		if e.Primary {
			return true
		}
	}
	return false
}

// matches reports whether the address matches attr eq want.
func (e Email) matches(attr, want string) bool {
	switch attr {
	case "value":
		return strings.EqualFold(e.Value, want)
	case "type":
		return strings.EqualFold(e.Type, want)
	case "primary":
		return want == "true" // the kept address is the primary
	}
	return false
}

// valueFilter parses a value filter of one equality, `attr eq "value"` or
// `primary eq true` (RFC 7644 §3.4.2.2), on value, type or primary.
func valueFilter(expr string) (attr, value string, err error) {
	bad := Fail(http.StatusBadRequest, "invalidFilter", "a filter on emails is one equality on value, type or primary")
	attr, rest, ok := cutField(expr)
	op, rest, ok2 := cutField(rest)
	if !ok || !ok2 || !strings.EqualFold(op, "eq") {
		return "", "", bad
	}
	attr, rest = strings.ToLower(attr), strings.TrimSpace(rest)
	switch {
	case attr == "primary" && (strings.EqualFold(rest, "true") || strings.EqualFold(rest, "false")):
		return attr, strings.ToLower(rest), nil
	case attr == "value" || attr == "type":
		v, after, err := cutString(rest)
		if err != nil || strings.TrimSpace(after) != "" {
			return "", "", bad
		}
		return attr, v, nil
	}
	return "", "", bad
}

func stringValue(path string, raw json.RawMessage) (string, error) {
	var s string
	if json.Unmarshal(raw, &s) != nil {
		return "", Fail(http.StatusBadRequest, "invalidValue", path+" takes a string")
	}
	return s, nil
}

// boolValue reads a boolean, or the strings "true" and "false" in any case,
// as Microsoft Entra ID sends them.
func boolValue(path string, raw json.RawMessage) (bool, error) {
	var b bool
	if json.Unmarshal(raw, &b) == nil {
		return b, nil
	}
	var s string
	if json.Unmarshal(raw, &s) == nil {
		switch strings.ToLower(strings.TrimSpace(s)) {
		case "true":
			return true, nil
		case "false":
			return false, nil
		}
	}
	return false, Fail(http.StatusBadRequest, "invalidValue", path+" takes a boolean")
}
