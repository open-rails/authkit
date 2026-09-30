package authkit

import "github.com/open-rails/authkit/internal/config"

// Deps is everything AuthKit reaches outside the process through: the store,
// keys, identity providers, senders and the host's hooks.
type Deps = config.Deps

type (
	// EmailSender delivers email and reports whether it can
	// (adapters/twilio.NewEmail).
	EmailSender = config.EmailSender
	// SMSSender delivers text messages and reports whether it can
	// (adapters/twilio.NewSMS).
	SMSSender = config.SMSSender
)
