package embedded

import (
	"context"
	"strings"

	"github.com/open-rails/authkit/documents"
)

// SignDocument signs through the Client's live key source, so normal AuthKit
// key rotation applies without exposing private key material to the host.
func (s *Client) SignDocument(ctx context.Context, envelope documents.Envelope) (documents.SignedDocument, error) {
	signer := s.keys.ActiveSigner()
	if signer == nil {
		return documents.SignedDocument{}, ErrMissingSigner
	}
	issuer := strings.TrimSpace(s.cfg.Token.Issuer)
	if strings.TrimSpace(envelope.Issuer) == "" {
		envelope.Issuer = issuer
	} else if issuer != "" && strings.TrimSpace(envelope.Issuer) != issuer {
		return documents.SignedDocument{}, documents.ErrIssuerMismatch
	}
	return documents.Sign(ctx, signer, envelope)
}
