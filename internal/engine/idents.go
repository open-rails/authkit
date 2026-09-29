package engine

import (
	"database/sql"
	"fmt"

	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/internal/ident"
)

// Rows store identifiers as their names; these Scan destinations build the
// typed values.

// ownerRoleName is the stored name of every persona's owner role.
const ownerRoleName = "owner"

// scanPersona scans a persona column into p.
func scanPersona(p *iam.Persona) sql.Scanner {
	return textScanner(func(s string) { *p = ident.Persona(s) })
}

// scanRole scans a role-name column of a group of persona into r.
func scanRole(r *iam.Role, persona iam.Persona) sql.Scanner {
	return textScanner(func(s string) { *r = ident.Role(persona, s) })
}

type textScanner func(string)

func (f textScanner) Scan(src any) error {
	switch v := src.(type) {
	case nil:
		f("")
	case string:
		f(v)
	case []byte:
		f(string(v))
	default:
		return fmt.Errorf("authkit: cannot scan %T into an identifier", src)
	}
	return nil
}
