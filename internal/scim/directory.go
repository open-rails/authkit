package scim

import (
	"errors"
	"net/http"
	"strings"
	"unicode/utf8"
)

// The limits of a directory User's attributes, in characters.
const (
	MaxSubject = 255 // OpenID Connect Core §2: sub is at most 255 ASCII characters
	MaxName    = 256
	MaxEmail   = 320
)

// ErrNoTenant is a credential that provisions no directory.
var ErrNoTenant = errors.New("scim: the credential provisions no remote application's users")

// Fail is a SCIM error to answer (RFC 7644 §3.12).
func Fail(status int, scimType, detail string) *StatusError {
	return &StatusError{Status: status, ScimType: scimType, Detail: detail}
}

// DirectoryUser is the part of a User a directory keeps, checked: what a
// create or replace stores.
type DirectoryUser struct {
	Subject, UserName                             string
	DisplayName, Formatted, GivenName, FamilyName string
	Email, EmailType                              string
	Active                                        bool
}

// Directory checks u as a directory stores it (RFC 7644 §3.3, §3.5.1):
// schemas names the User schema, userName and externalId (the subject at the
// issuer) are required, the primary address (else the first) is the one kept,
// active defaults to true. Values are trimmed; an empty one is absent.
func (u User) Directory() (DirectoryUser, error) {
	if !containsFold(u.Schemas, SchemaUser) {
		return DirectoryUser{}, Fail(http.StatusBadRequest, "invalidSyntax", "schemas must name "+SchemaUser)
	}
	email := primary(u.Emails)
	out := DirectoryUser{
		Subject: strings.TrimSpace(u.ExternalID), UserName: strings.TrimSpace(u.UserName), DisplayName: strings.TrimSpace(u.DisplayName),
		Email: strings.TrimSpace(email.Value), EmailType: strings.TrimSpace(email.Type), Active: u.Active == nil || *u.Active,
	}
	if u.Name != nil {
		out.Formatted, out.GivenName, out.FamilyName = strings.TrimSpace(u.Name.Formatted), strings.TrimSpace(u.Name.GivenName), strings.TrimSpace(u.Name.FamilyName)
	}
	switch {
	case out.UserName == "":
		return DirectoryUser{}, Fail(http.StatusBadRequest, "invalidValue", "userName is required")
	case out.Subject == "":
		return DirectoryUser{}, Fail(http.StatusBadRequest, "invalidValue", "externalId is required: the user's subject (sub) at its issuer")
	case utf8.RuneCountInString(out.Subject) > MaxSubject:
		return DirectoryUser{}, Fail(http.StatusBadRequest, "invalidValue", "externalId is longer than 255 characters")
	case utf8.RuneCountInString(out.Email) > MaxEmail || out.Email != "" && !strings.Contains(out.Email, "@"):
		return DirectoryUser{}, Fail(http.StatusBadRequest, "invalidValue", "the email address is not one")
	}
	for name, v := range map[string]string{"userName": out.UserName, "displayName": out.DisplayName, "name.formatted": out.Formatted,
		"name.givenName": out.GivenName, "name.familyName": out.FamilyName, "emails.type": out.EmailType} {
		if utf8.RuneCountInString(v) > MaxName {
			return DirectoryUser{}, Fail(http.StatusBadRequest, "invalidValue", name+" is longer than 256 characters")
		}
	}
	return out, nil
}

// Name is how a directory user is named: displayName, else
// name.formatted, else the given and family names.
func (u DirectoryUser) Name() string {
	switch {
	case u.DisplayName != "":
		return u.DisplayName
	case u.Formatted != "":
		return u.Formatted
	}
	return strings.TrimSpace(u.GivenName + " " + u.FamilyName)
}

// DirectoryUserSchema is the User schema a directory serves (RFC 7643 §4.1,
// §7): the attributes it keeps, all readWrite. externalId, a common
// attribute (RFC 7643 §3.1), is the user's subject at its issuer and
// required.
func DirectoryUserSchema() SchemaDoc {
	attr := func(name, description string, required bool, uniqueness string) Attribute {
		return Attribute{Name: name, Type: "string", Description: description, Required: required,
			Mutability: "readWrite", Returned: "default", Uniqueness: uniqueness}
	}
	return SchemaDoc{
		Schemas: []string{SchemaSchema}, ID: SchemaUser, Name: "User", Description: "User Account",
		Attributes: []Attribute{
			attr("userName", "Unique among the issuer's users here.", true, "server"),
			{Name: "name", Type: "complex", Description: "The user's name.", Mutability: "readWrite", Returned: "default", Uniqueness: "none",
				SubAttributes: []Attribute{
					attr("formatted", "The full name.", false, "none"),
					attr("givenName", "The given name.", false, "none"),
					attr("familyName", "The family name.", false, "none"),
				}},
			attr("displayName", "The name to show.", false, "none"),
			{Name: "emails", Type: "complex", MultiValued: true, Mutability: "readWrite", Returned: "default", Uniqueness: "none",
				Description: "One address is kept: the primary, else the first. Every address pushed is taken as one the issuer has verified.",
				SubAttributes: []Attribute{
					attr("value", "The address.", false, "none"),
					attr("type", "Its label, such as work.", false, "none"),
					{Name: "primary", Type: "boolean", Description: "Always true: the kept address.", Mutability: "readWrite", Returned: "default", Uniqueness: "none"},
				}},
			{Name: "active", Type: "boolean", Description: "Whether the issuer lets the user act; default true. An inactive user's contact is not served.", Mutability: "readWrite", Returned: "default", Uniqueness: "none"},
		},
	}
}

func containsFold(list []string, s string) bool {
	for _, v := range list {
		if strings.EqualFold(strings.TrimSpace(v), s) {
			return true
		}
	}
	return false
}
