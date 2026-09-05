package authkit

import "context"

type languageKey struct{}

// WithLanguage attaches a request language to ctx.
func WithLanguage(ctx context.Context, language string) context.Context {
	return context.WithValue(ctx, languageKey{}, language)
}

// LanguageFromContext reads the request language attached by WithLanguage.
func LanguageFromContext(ctx context.Context) (string, bool) {
	s, ok := ctx.Value(languageKey{}).(string)
	return s, ok && s != ""
}
