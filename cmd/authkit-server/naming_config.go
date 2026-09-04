package main

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	authkit "github.com/open-rails/authkit"
)

func namingConfigFromEnv() (authkit.NamingConfig, error) {
	var c authkit.NamingConfig
	if raw, exists := os.LookupEnv("AUTHKIT_NAMING_ENABLED"); exists {
		enabled, err := strconv.ParseBool(strings.TrimSpace(raw))
		if err != nil {
			return c, fmt.Errorf("AUTHKIT_NAMING_ENABLED: %w", err)
		}
		c.Enabled = &enabled
	}
	for _, field := range []struct {
		name string
		dst  **time.Duration
	}{
		{"AUTHKIT_NAMING_RENAME_INTERVAL", &c.RenameInterval},
		{"AUTHKIT_NAMING_FORMER_NAMES_DURATION", &c.FormerNames.Duration},
	} {
		if raw, exists := os.LookupEnv(field.name); exists {
			duration, err := time.ParseDuration(strings.TrimSpace(raw))
			if err != nil {
				return c, fmt.Errorf("%s: %w", field.name, err)
			}
			*field.dst = &duration
		}
	}
	c.FormerNames.Mode = authkit.FormerNameRetentionMode(strings.TrimSpace(os.Getenv("AUTHKIT_NAMING_FORMER_NAMES_MODE")))
	// The library uses this exact normalization at construction. Validate here
	// too so the standalone process refuses before opening stores/listeners.
	_, err := c.Normalize()
	return c, err
}
