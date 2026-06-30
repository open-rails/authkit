package authcore

import (
	"context"
	"fmt"
	"regexp"
	"strings"

	authkit "github.com/open-rails/authkit"
	"github.com/open-rails/authkit/internal/db"
	authlang "github.com/open-rails/authkit/lang"
)

// Preferred-language: validation, get/set on the user profile, and the
// context helpers that thread the active language through send flows.

var preferredLanguageRe = regexp.MustCompile(`^[A-Za-z]{2}$`)

func NormalizePreferredLanguage(language string) (string, error) {
	language = strings.TrimSpace(strings.ToLower(language))
	if language == "" {
		return "", nil
	}
	if !preferredLanguageRe.MatchString(language) {
		return "", fmt.Errorf("invalid_preferred_language")
	}
	return language, nil
}

type PreferredLanguage = authkit.PreferredLanguage

func (s *Service) SetPreferredLanguage(ctx context.Context, userID, language string) error {
	if s.pg == nil {
		return fmt.Errorf("postgres not configured")
	}
	userID = strings.TrimSpace(userID)
	normalized, err := NormalizePreferredLanguage(language)
	if err != nil {
		return err
	}
	if userID == "" || normalized == "" {
		return fmt.Errorf("invalid_request")
	}
	return s.q.UserSetPreferredLanguage(ctx, db.UserSetPreferredLanguageParams{ID: userID, PreferredLanguage: &normalized})
}

func (s *Service) GetPreferredLanguage(ctx context.Context, userID string) (PreferredLanguage, error) {
	if s.pg == nil {
		return PreferredLanguage{}, nil
	}
	row, err := s.q.UserPreferredLanguage(ctx, strings.TrimSpace(userID))
	return PreferredLanguage{Language: row}, err
}

func contextWithPreferredLanguage(ctx context.Context, language string) context.Context {
	if strings.TrimSpace(language) == "" {
		return ctx
	}
	return authlang.WithLanguage(ctx, language)
}

func (s *Service) contextWithUserPreferredLanguage(ctx context.Context, userID string) context.Context {
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
