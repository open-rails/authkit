package httpapi

import (
	"encoding"
	"encoding/json"
	"fmt"
	"reflect"
	"regexp"
	"strings"
	"time"
)

// The wire model: how a Go type the handlers marshal appears in JSON. The
// contract generator renders it as OpenAPI and TypeScript, and Conform checks
// real responses against it.

const module = "github.com/open-rails/authkit"

// WireKind is a Go type's JSON form.
type WireKind int

const (
	WireString WireKind = iota
	WireInteger
	WireNumber
	WireBoolean
	WireTime  // RFC 3339 in UTC
	WireBytes // base64
	WireAny   // arbitrary JSON
	WireOpaque
	WireArray
	WireMap
	WireNullable
	WireObject // a named AuthKit struct
	WirePage   // iam.ListPage[T]
)

var (
	timeType          = reflect.TypeFor[time.Time]()
	rawMessageType    = reflect.TypeFor[json.RawMessage]()
	jsonMarshalerType = reflect.TypeFor[json.Marshaler]()
	textMarshalerType = reflect.TypeFor[encoding.TextMarshaler]()
)

// KindOf is t's JSON form. A struct defined outside AuthKit is opaque.
func KindOf(t reflect.Type) WireKind {
	switch {
	case t == timeType:
		return WireTime
	case t == rawMessageType:
		return WireAny
	case IsPage(t):
		return WirePage
	case t.Kind() == reflect.Pointer:
		return WireNullable
	case t.Implements(textMarshalerType):
		return WireString
	}
	switch t.Kind() {
	case reflect.String:
		return WireString
	case reflect.Bool:
		return WireBoolean
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64,
		reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		return WireInteger
	case reflect.Float32, reflect.Float64:
		return WireNumber
	case reflect.Slice, reflect.Array:
		if t.Elem().Kind() == reflect.Uint8 {
			return WireBytes
		}
		return WireArray
	case reflect.Map:
		return WireMap
	case reflect.Interface:
		return WireAny
	case reflect.Struct:
		if !strings.HasPrefix(t.PkgPath(), module) {
			return WireOpaque
		}
		return WireObject
	}
	panic(fmt.Sprintf("httpapi: no wire form for %s", t))
}

// IsPage reports whether t is iam.ListPage[T].
func IsPage(t reflect.Type) bool {
	return t.Kind() == reflect.Struct && t.PkgPath() == module+"/iam" && strings.HasPrefix(t.Name(), "ListPage[")
}

// PageItem is T of iam.ListPage[T].
func PageItem(t reflect.Type) reflect.Type { return t.Field(0).Type.Elem() }

// WireField is one JSON member of an object.
type WireField struct {
	Name string
	Type reflect.Type
	// Optional marks an omitempty member, absent when zero: only protocol
	// documents (JWKS) have them.
	Optional bool
	// Tag is the field's full json tag.
	Tag string
}

// Fields lists t's JSON members; embedded structs contribute theirs.
func Fields(t reflect.Type) []WireField {
	var out []WireField
	for i := range t.NumField() {
		f := t.Field(i)
		if !f.IsExported() {
			continue
		}
		tag := f.Tag.Get("json")
		name, opts, _ := strings.Cut(tag, ",")
		if name == "-" {
			continue
		}
		if f.Anonymous && name == "" && f.Type.Kind() == reflect.Struct {
			out = append(out, Fields(f.Type)...)
			continue
		}
		if name == "" {
			name = f.Name
		}
		out = append(out, WireField{Name: name, Type: f.Type, Tag: tag, Optional: strings.Contains(","+opts+",", ",omitempty,")})
	}
	return out
}

var utcTime = regexp.MustCompile(`^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?Z$`)

// Conform checks decoded JSON v against t's wire form and lists every
// difference: a missing or unknown member, a null where none is allowed, a
// wrong JSON type, a time not in UTC.
func Conform(t reflect.Type, v any) []string {
	var out []string
	conform(t, v, "$", &out)
	return out
}

func conform(t reflect.Type, v any, path string, out *[]string) {
	bad := func(format string, args ...any) { *out = append(*out, path+": "+fmt.Sprintf(format, args...)) }
	kind := KindOf(t)
	if v == nil {
		if kind != WireNullable && kind != WireAny {
			bad("null, want %s", t)
		}
		return
	}
	switch kind {
	case WireNullable:
		conform(t.Elem(), v, path, out)
	case WireAny:
	case WireString, WireBytes:
		if _, ok := v.(string); !ok {
			bad("%T, want a string", v)
		}
	case WireTime:
		if s, ok := v.(string); !ok || !utcTime.MatchString(s) {
			bad("%v, want an RFC 3339 time in UTC", v)
		}
	case WireInteger:
		if f, ok := v.(float64); !ok || f != float64(int64(f)) {
			bad("%v, want an integer", v)
		}
	case WireNumber:
		if _, ok := v.(float64); !ok {
			bad("%T, want a number", v)
		}
	case WireBoolean:
		if _, ok := v.(bool); !ok {
			bad("%T, want a boolean", v)
		}
	case WireArray:
		items, ok := v.([]any)
		if !ok {
			bad("%T, want an array", v)
			return
		}
		for i, item := range items {
			conform(t.Elem(), item, fmt.Sprintf("%s[%d]", path, i), out)
		}
	case WireMap:
		m, ok := v.(map[string]any)
		if !ok {
			bad("%T, want an object", v)
			return
		}
		for k, item := range m {
			conform(t.Elem(), item, path+"."+k, out)
		}
	case WireOpaque:
		if _, ok := v.(map[string]any); !ok {
			bad("%T, want an object", v)
		}
	case WirePage:
		members(map[string]reflect.Type{
			"data": reflect.SliceOf(PageItem(t)), "next_cursor": reflect.TypeFor[*string](), "total": reflect.TypeFor[*int](),
		}, nil, v, path, out)
	case WireObject:
		fields := Fields(t)
		types := make(map[string]reflect.Type, len(fields))
		optional := map[string]bool{}
		for _, f := range fields {
			types[f.Name], optional[f.Name] = f.Type, f.Optional
		}
		members(types, optional, v, path, out)
	}
}

func members(types map[string]reflect.Type, optional map[string]bool, v any, path string, out *[]string) {
	m, ok := v.(map[string]any)
	if !ok {
		*out = append(*out, fmt.Sprintf("%s: %T, want an object", path, v))
		return
	}
	for name, t := range types {
		value, present := m[name]
		if !present {
			if !optional[name] {
				*out = append(*out, path+"."+name+": missing")
			}
			continue
		}
		conform(t, value, path+"."+name, out)
	}
	for name := range m {
		if _, known := types[name]; !known {
			*out = append(*out, path+"."+name+": not in the contract")
		}
	}
}
