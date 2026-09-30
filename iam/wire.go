package iam

// Wire shapes shared by every HTTP success response (#313). Error responses
// use ErrorEnvelope; these are the success-side vocabulary, defined once here
// so HTTP handlers marshal typed values instead of map literals.

// TokenSet is the one session-token envelope. A session-establishing route
// returns it as the whole body, or under "token_set" when the response says
// more (registration, step-up, device keys, SIWS/passwordless extras).
// RefreshToken is nil when none is issued, or when the mount's refresh
// cookie carries it.
type TokenSet struct {
	AccessToken  string  `json:"access_token"`
	TokenType    string  `json:"token_type"`
	ExpiresIn    int64   `json:"expires_in"`
	RefreshToken *string `json:"refresh_token"`
}
