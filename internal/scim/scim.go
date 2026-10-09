// Package scim is the SCIM 2.0 wire format (RFC 7643, RFC 7644) AuthKit
// speaks both ways: the User resource, list and error messages, bulk
// requests, discovery documents, the filter subset its service provider
// answers, and the client its provisioning pushes with.
package scim

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// MediaType is SCIM's content type.
const MediaType = "application/scim+json"

// MaxResults caps one page of AuthKit's GET /Users.
const MaxResults = 200

// Schema URNs.
const (
	SchemaUser                  = "urn:ietf:params:scim:schemas:core:2.0:User"
	SchemaListResponse          = "urn:ietf:params:scim:api:messages:2.0:ListResponse"
	SchemaError                 = "urn:ietf:params:scim:api:messages:2.0:Error"
	SchemaBulkRequest           = "urn:ietf:params:scim:api:messages:2.0:BulkRequest"
	SchemaBulkResponse          = "urn:ietf:params:scim:api:messages:2.0:BulkResponse"
	SchemaServiceProviderConfig = "urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig"
	SchemaResourceType          = "urn:ietf:params:scim:schemas:core:2.0:ResourceType"
	SchemaSchema                = "urn:ietf:params:scim:schemas:core:2.0:Schema"
)

// User is the core User resource, as much of it as AuthKit sends and reads.
type User struct {
	Schemas     []string `json:"schemas"`
	ID          string   `json:"id,omitempty"`
	ExternalID  string   `json:"externalId,omitempty"`
	UserName    string   `json:"userName"`
	Name        *Name    `json:"name,omitempty"`
	DisplayName string   `json:"displayName,omitempty"`
	Emails      []Email  `json:"emails,omitempty"`
	Active      *bool    `json:"active,omitempty"`
	Meta        *Meta    `json:"meta,omitempty"`
}

// Name is the User's name; AuthKit keeps only the display form.
type Name struct {
	Formatted string `json:"formatted,omitempty"`
}

// Email is one of the User's addresses.
type Email struct {
	Value   string `json:"value"`
	Primary bool   `json:"primary,omitempty"`
}

// Meta is a resource's metadata.
type Meta struct {
	ResourceType string     `json:"resourceType,omitempty"`
	Created      *time.Time `json:"created,omitempty"`
	LastModified *time.Time `json:"lastModified,omitempty"`
	Location     string     `json:"location,omitempty"`
}

// PrimaryEmail is the primary address, else the first; "" without one.
func (u User) PrimaryEmail() string {
	for _, e := range u.Emails {
		if e.Primary {
			return e.Value
		}
	}
	if len(u.Emails) > 0 {
		return u.Emails[0].Value
	}
	return ""
}

// ListResponse is a query's page (RFC 7644 §3.4.2).
type ListResponse[T any] struct {
	Schemas      []string `json:"schemas"`
	TotalResults int      `json:"totalResults"`
	StartIndex   int      `json:"startIndex"`
	ItemsPerPage int      `json:"itemsPerPage"`
	Resources    []T      `json:"Resources"`
}

// Error is an error response (RFC 7644 §3.12). Status is the HTTP status as
// a string, as the RFC's examples send it.
type Error struct {
	Schemas  []string `json:"schemas"`
	Status   string   `json:"status"`
	ScimType string   `json:"scimType,omitempty"`
	Detail   string   `json:"detail,omitempty"`
}

// NewError is an error response for status.
func NewError(status int, scimType, detail string) Error {
	return Error{Schemas: []string{SchemaError}, Status: strconv.Itoa(status), ScimType: scimType, Detail: detail}
}

// Status is an HTTP status a SCIM peer sent as a JSON string or number.
type Status int

func (s *Status) UnmarshalJSON(b []byte) error {
	var n int
	if err := json.Unmarshal(b, &n); err == nil {
		*s = Status(n)
		return nil
	}
	var text string
	if err := json.Unmarshal(b, &text); err != nil {
		return fmt.Errorf("scim: status %s is neither a number nor a string", b)
	}
	// "201", or a reason phrase after the code ("201 Created").
	code, _, _ := strings.Cut(strings.TrimSpace(text), " ")
	n, err := strconv.Atoi(code)
	if err != nil {
		return fmt.Errorf("scim: status %q is not an HTTP status", text)
	}
	*s = Status(n)
	return nil
}

// BulkRequest is a bulk request (RFC 7644 §3.7).
type BulkRequest struct {
	Schemas      []string        `json:"schemas"`
	FailOnErrors *int            `json:"failOnErrors,omitempty"`
	Operations   []BulkOperation `json:"Operations"`
}

// BulkOperation is one operation of a bulk request.
type BulkOperation struct {
	Method string `json:"method"`
	BulkID string `json:"bulkId,omitempty"`
	Path   string `json:"path"`
	Data   any    `json:"data,omitempty"`
}

// BulkResponse answers a bulk request.
type BulkResponse struct {
	Schemas    []string     `json:"schemas"`
	Operations []BulkResult `json:"Operations"`
}

// BulkResult is one operation's outcome. Response holds an error's detail.
type BulkResult struct {
	Location string          `json:"location,omitempty"`
	Method   string          `json:"method,omitempty"`
	BulkID   string          `json:"bulkId,omitempty"`
	Status   Status          `json:"status"`
	Response json.RawMessage `json:"response,omitempty"`
}

// ServiceProviderConfig is the discovery document of RFC 7643 §5.
type ServiceProviderConfig struct {
	Schemas               []string      `json:"schemas"`
	DocumentationURI      string        `json:"documentationUri,omitempty"`
	Patch                 Supported     `json:"patch"`
	Bulk                  BulkSupport   `json:"bulk"`
	Filter                FilterSupport `json:"filter"`
	ChangePassword        Supported     `json:"changePassword"`
	Sort                  Supported     `json:"sort"`
	ETag                  Supported     `json:"etag"`
	AuthenticationSchemes []AuthScheme  `json:"authenticationSchemes"`
	Meta                  *Meta         `json:"meta,omitempty"`
}

// Supported is a feature a service provider has or lacks.
type Supported struct {
	Supported bool `json:"supported"`
}

// BulkSupport is the bulk feature and its limits.
type BulkSupport struct {
	Supported      bool `json:"supported"`
	MaxOperations  int  `json:"maxOperations"`
	MaxPayloadSize int  `json:"maxPayloadSize"`
}

// FilterSupport is the filter feature and its result cap.
type FilterSupport struct {
	Supported  bool `json:"supported"`
	MaxResults int  `json:"maxResults"`
}

// AuthScheme is how a client authenticates.
type AuthScheme struct {
	Type        string `json:"type"`
	Name        string `json:"name"`
	Description string `json:"description"`
	SpecURI     string `json:"specUri,omitempty"`
	Primary     bool   `json:"primary,omitempty"`
}

// ResourceType describes one resource endpoint (RFC 7643 §6).
type ResourceType struct {
	Schemas     []string `json:"schemas"`
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Endpoint    string   `json:"endpoint"`
	Description string   `json:"description,omitempty"`
	Schema      string   `json:"schema"`
	Meta        *Meta    `json:"meta,omitempty"`
}

// SchemaDoc describes a schema's attributes (RFC 7643 §7).
type SchemaDoc struct {
	Schemas     []string    `json:"schemas,omitempty"`
	ID          string      `json:"id"`
	Name        string      `json:"name"`
	Description string      `json:"description,omitempty"`
	Attributes  []Attribute `json:"attributes"`
	Meta        *Meta       `json:"meta,omitempty"`
}

// Attribute describes one attribute of a schema.
type Attribute struct {
	Name          string      `json:"name"`
	Type          string      `json:"type"`
	MultiValued   bool        `json:"multiValued"`
	Description   string      `json:"description,omitempty"`
	Required      bool        `json:"required"`
	CaseExact     bool        `json:"caseExact"`
	Mutability    string      `json:"mutability"`
	Returned      string      `json:"returned"`
	Uniqueness    string      `json:"uniqueness"`
	SubAttributes []Attribute `json:"subAttributes,omitempty"`
}

// UserSchema is the part of the core User schema AuthKit serves.
func UserSchema() SchemaDoc {
	str := func(name, description string, required, caseExact bool, uniqueness string) Attribute {
		return Attribute{Name: name, Type: "string", Description: description, Required: required, CaseExact: caseExact,
			Mutability: "readOnly", Returned: "default", Uniqueness: uniqueness}
	}
	return SchemaDoc{
		Schemas: []string{SchemaSchema}, ID: SchemaUser, Name: "User", Description: "User Account",
		Attributes: []Attribute{
			str("userName", "The account's username, or its id when it has none.", true, false, "server"),
			{Name: "name", Type: "complex", Description: "The account's name.", Mutability: "readOnly", Returned: "default", Uniqueness: "none",
				SubAttributes: []Attribute{str("formatted", "The display name.", false, false, "none")}},
			str("displayName", "The display name.", false, false, "none"),
			{Name: "emails", Type: "complex", MultiValued: true, Description: "The account's verified email address.", Mutability: "readOnly", Returned: "default", Uniqueness: "none",
				SubAttributes: []Attribute{
					str("value", "The address.", false, false, "none"),
					{Name: "primary", Type: "boolean", Description: "The primary address.", Mutability: "readOnly", Returned: "default", Uniqueness: "none"},
				}},
			{Name: "active", Type: "boolean", Description: "Neither deleted nor banned.", Mutability: "readOnly", Returned: "default", Uniqueness: "none"},
		},
	}
}
