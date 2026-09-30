package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"reflect"
	"strconv"
	"strings"

	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/internal/config"
	"github.com/open-rails/authkit/internal/errmodel"
	"github.com/open-rails/authkit/internal/httpapi"
)

const defaultAPIPath = config.DefaultAPIPath

// obj is a JSON object whose keys keep their insertion order, so the
// generated document is stable and reads top-down.
type obj struct {
	keys []string
	vals map[string]any
}

func newObj(kv ...any) *obj {
	o := &obj{vals: map[string]any{}}
	for i := 0; i+1 < len(kv); i += 2 {
		o.set(kv[i].(string), kv[i+1])
	}
	return o
}

func (o *obj) set(k string, v any) *obj {
	if _, ok := o.vals[k]; !ok {
		o.keys = append(o.keys, k)
	}
	o.vals[k] = v
	return o
}

func (o *obj) MarshalJSON() ([]byte, error) {
	var b bytes.Buffer
	b.WriteByte('{')
	for i, k := range o.keys {
		if i > 0 {
			b.WriteByte(',')
		}
		key, _ := json.Marshal(k)
		b.Write(key)
		b.WriteByte(':')
		val, err := marshal(o.vals[k])
		if err != nil {
			return nil, err
		}
		b.Write(val)
	}
	b.WriteByte('}')
	return b.Bytes(), nil
}

func marshal(v any) ([]byte, error) {
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	return bytes.TrimRight(b.Bytes(), "\n"), nil
}

// schema is t's JSON Schema. Required members are always present; a nullable
// value admits null.
func (c *contract) schema(t reflect.Type) *obj {
	switch classify(t) {
	case kindString:
		if values := enumValues(t); values != nil {
			return newObj("type", "string", "enum", values)
		}
		return newObj("type", "string")
	case kindInteger:
		return newObj("type", "integer")
	case kindNumber:
		return newObj("type", "number")
	case kindBoolean:
		return newObj("type", "boolean")
	case kindTime:
		return newObj("type", "string", "format", "date-time", "description", "RFC 3339, UTC")
	case kindBytes:
		return newObj("type", "string", "contentEncoding", "base64")
	case kindAny:
		return newObj()
	case kindOpaque:
		return newObj("type", "object", "description", "Defined outside AuthKit: "+t.String())
	case kindArray:
		return newObj("type", "array", "items", c.schema(t.Elem()))
	case kindMap:
		return newObj("type", "object", "additionalProperties", c.schema(t.Elem()))
	case kindNullable:
		return newObj("oneOf", []any{c.schema(t.Elem()), newObj("type", "null")})
	case kindPage:
		return newObj("$ref", "#/components/schemas/"+pageName(t))
	}
	return newObj("$ref", "#/components/schemas/"+wireName(t))
}

func pageName(t reflect.Type) string { return wireName(pageItem(t)) + "Page" }

func (c *contract) objectSchema(o *object) *obj {
	props := newObj()
	var required []string
	for _, f := range o.fields {
		props.set(f.name, c.schema(f.t))
		if o.output && !f.optional {
			required = append(required, f.name)
		}
	}
	s := newObj("type", "object", "properties", props)
	if len(required) > 0 {
		s.set("required", required)
	}
	return s
}

func (c *contract) pageSchema(item reflect.Type) *obj {
	return newObj("type", "object",
		"description", "One page of a list. next_cursor is null on the last page; total is null unless asked for.",
		"properties", newObj(
			"data", newObj("type", "array", "items", c.schema(item)),
			"next_cursor", newObj("type", []string{"string", "null"}),
			"total", newObj("type", []string{"integer", "null"}),
		),
		"required", []string{"data", "next_cursor", "total"})
}

func (c *contract) openAPI() ([]byte, error) {
	schemas := newObj()
	pages := map[string]reflect.Type{}
	var collect func(t reflect.Type)
	collect = func(t reflect.Type) {
		switch classify(t) {
		case kindNullable, kindArray, kindMap:
			collect(t.Elem())
		case kindPage:
			pages[pageName(t)] = pageItem(t)
		}
	}
	for _, o := range c.sortedObjects() {
		for _, f := range o.fields {
			collect(f.t)
		}
	}
	for _, r := range c.routes {
		for _, reply := range r.Responses {
			if reply.Body != nil {
				collect(reflect.TypeOf(reply.Body))
			}
		}
	}
	for _, o := range c.sortedObjects() {
		schemas.set(o.name, c.objectSchema(o))
	}
	for _, name := range sortedKeys(pages) {
		schemas.set(name, c.pageSchema(pages[name]))
	}
	env := reflect.TypeFor[iam.ErrorEnvelope]()
	schemas.set("ErrorEnvelope", newObj("type", "object",
		"properties", newObj("error", newObj("$ref", "#/components/schemas/ErrorObject")),
		"required", []string{"error"}))
	errObj := &object{name: "ErrorObject", t: env.Field(0).Type, fields: fieldsOf(env.Field(0).Type), output: true}
	errSchema := c.objectSchema(errObj)
	errSchema.vals["properties"].(*obj).set("metadata", newObj("type", []string{"object", "null"}))
	errSchema.set("description", "type follows the status; code is stable (clients tolerate new ones); message is not contract.")
	schemas.set("ErrorObject", errSchema)

	paths := newObj()
	for _, r := range c.routes {
		path := fullPath(r)
		item, _ := paths.vals[path].(*obj)
		if item == nil {
			item = newObj()
			paths.set(path, item)
		}
		item.set(strings.ToLower(r.Method), c.operation(r))
	}

	codes := newObj()
	for _, code := range errmodel.Codes() {
		codes.set(string(code), newObj("status", errmodel.Status(code), "message", errmodel.Message(code)))
	}
	doc := newObj(
		"openapi", "3.1.0",
		"info", newObj(
			"title", "AuthKit",
			"version", "v1",
			"description", "AuthKit's HTTP API on a default mount: the JSON API beneath /api/v1, browser OIDC beneath /oidc, JWKS at the issuer's path. "+
				"Generated from the route catalog (internal/httpapi/catalog.go) by go generate ./internal/httpapi; do not edit.",
		),
		"paths", paths,
		"components", newObj(
			"schemas", schemas,
			"securitySchemes", newObj("bearer", newObj("type", "http", "scheme", "bearer",
				"description", "An access token (JWT) or an API key.")),
		),
		"x-authkit-error-codes", codes,
	)
	out, err := marshalIndent(doc)
	if err != nil {
		return nil, err
	}
	return append(out, '\n'), nil
}

func marshalIndent(v any) ([]byte, error) {
	raw, err := marshal(v)
	if err != nil {
		return nil, err
	}
	var b bytes.Buffer
	if err := json.Indent(&b, raw, "", "  "); err != nil {
		return nil, err
	}
	return b.Bytes(), nil
}

func (c *contract) operation(r httpapi.RouteSpec) *obj {
	op := newObj("tags", []string{string(r.Group)})
	var params []any
	for _, p := range pathParams(r.Path) {
		params = append(params, newObj("name", p, "in", "path", "required", true, "schema", newObj("type", "string")))
	}
	for _, q := range queryParams(r.Query) {
		p := newObj("name", q.name, "in", "query", "schema", c.schema(q.t))
		if q.t.Kind() == reflect.Slice {
			p.set("explode", true)
		}
		params = append(params, p)
	}
	if len(params) > 0 {
		op.set("parameters", params)
	}
	if r.Request != nil {
		op.set("requestBody", newObj(
			"required", r.Method != http.MethodDelete,
			"content", newObj("application/json", newObj("schema", c.schema(reflect.TypeOf(r.Request)))),
		))
	}
	responses := newObj()
	for _, reply := range r.Responses {
		resp := newObj("description", http.StatusText(reply.Status))
		if reply.Body != nil {
			resp.set("content", newObj("application/json", newObj("schema", c.schema(reflect.TypeOf(reply.Body)))))
		}
		responses.set(strconv.Itoa(reply.Status), resp)
	}
	responses.set("default", newObj("description", "An error",
		"content", newObj("application/json", newObj("schema", newObj("$ref", "#/components/schemas/ErrorEnvelope")))))
	op.set("responses", responses)
	if r.Auth == iam.AuthPublic {
		op.set("security", []any{})
	} else {
		op.set("security", []any{newObj("bearer", []string{})})
	}
	op.set("x-authkit-auth", string(r.Auth))
	if r.Perm != "" {
		op.set("x-authkit-permission", r.Perm)
	}
	if r.Bucket != "" {
		op.set("x-authkit-rate-limit", r.Bucket)
	}
	if r.MountedWhen != httpapi.Always {
		op.set("x-authkit-mounted-when", string(r.MountedWhen))
	}
	if r.MFAEnrollmentExempt {
		op.set("x-authkit-mfa-enrollment-exempt", true)
	}
	return op
}
