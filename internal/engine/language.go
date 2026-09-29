package engine

import (
	"context"
	"strings"

	"github.com/open-rails/authkit/iam"
)

// Preferred-language: validation, get/set on the user profile, and the
// context helpers that thread the active language through send flows.

func contextWithPreferredLanguage(ctx context.Context, language string) context.Context {
	if strings.TrimSpace(language) == "" {
		return ctx
	}
	return iam.WithLanguage(ctx, language)
}

func (s *Engine) contextWithUserPreferredLanguage(ctx context.Context, userID string) context.Context {
	userID = strings.TrimSpace(userID)
	if userID == "" {
		return ctx
	}
	if s.pg == nil {
		return ctx
	}
	language, err := s.q.UserPreferredLanguage(ctx, userID)
	if err != nil {
		return ctx
	}
	return contextWithPreferredLanguage(ctx, language)
}
