// Package lang is AuthKit's one language normalizer and the request language
// the HTTP layer hands the engine.
package lang

import (
	"context"
	"strings"
)

// Default is the language of a message when nothing else chooses one.
const Default = "en"

// Normalize returns tag's two-letter lowercase language ("en-US" and "EN_us"
// give "en"), or "" when tag names none.
func Normalize(tag string) string {
	tag = strings.ToLower(strings.TrimSpace(tag))
	if i := strings.IndexAny(tag, "-_"); i >= 0 {
		tag = tag[:i]
	}
	if len(tag) != 2 || tag[0] < 'a' || tag[0] > 'z' || tag[1] < 'a' || tag[1] > 'z' {
		return ""
	}
	return tag
}

type ctxKey struct{}

// WithRequest attaches the request's negotiated language to ctx.
func WithRequest(ctx context.Context, language string) context.Context {
	if language = Normalize(language); language == "" {
		return ctx
	}
	return context.WithValue(ctx, ctxKey{}, language)
}

// Request is the language WithRequest attached, "" when none.
func Request(ctx context.Context) string {
	s, _ := ctx.Value(ctxKey{}).(string)
	return s
}
