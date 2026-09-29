package authkit

import (
	"context"
	"fmt"
	"strings"

	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/internal/authflow"
	"github.com/open-rails/authkit/internal/db"
)

// Preferred-language: validation, get/set on the user profile, and the
// context helpers that thread the active language through send flows.

func (s *engine) SetPreferredLanguage(ctx context.Context, userID, language string) error {
	if s.pg == nil {
		return fmt.Errorf("postgres not configured")
	}
	userID = strings.TrimSpace(userID)
	normalized, err := authflow.NormalizePreferredLanguage(language)
	if err != nil {
		return err
	}
	if userID == "" || normalized == "" {
		return fmt.Errorf("invalid_request")
	}
	return s.q.UserSetPreferredLanguage(ctx, db.UserSetPreferredLanguageParams{ID: userID, PreferredLanguage: &normalized})
}

func (s *engine) GetPreferredLanguage(ctx context.Context, userID string) (authflow.PreferredLanguage, error) {
	if s.pg == nil {
		return authflow.PreferredLanguage{}, nil
	}
	row, err := s.q.UserPreferredLanguage(ctx, strings.TrimSpace(userID))
	return authflow.PreferredLanguage{Language: row}, err
}

func contextWithPreferredLanguage(ctx context.Context, language string) context.Context {
	if strings.TrimSpace(language) == "" {
		return ctx
	}
	return iam.WithLanguage(ctx, language)
}

func (s *engine) contextWithUserPreferredLanguage(ctx context.Context, userID string) context.Context {
	userID = strings.TrimSpace(userID)
	if userID == "" {
		return ctx
	}
	preferred, err := s.GetPreferredLanguage(ctx, userID)
	if err != nil || strings.TrimSpace(preferred.Language) == "" {
		return ctx
	}
	return contextWithPreferredLanguage(ctx, preferred.Language)
}
