package authkit

import (
	"context"
	"strings"

	"github.com/open-rails/authkit/documents"
	"github.com/open-rails/authkit/iam"
)

// SignDocument signs through the engine's live key source, so normal AuthKit
// key rotation applies without exposing private key material to the host.
func (s *engine) SignDocument(ctx context.Context, envelope documents.Envelope) (documents.SignedDocument, error) {
	signer := s.keys.ActiveSigner()
	if signer == nil {
		return documents.SignedDocument{}, iam.ErrMissingSigner
	}
	issuer := strings.TrimSpace(s.cfg.Token.Issuer)
	if strings.TrimSpace(envelope.Issuer) == "" {
		envelope.Issuer = issuer
	} else if issuer != "" && strings.TrimSpace(envelope.Issuer) != issuer {
		return documents.SignedDocument{}, documents.ErrIssuerMismatch
	}
	return documents.Sign(ctx, signer, envelope)
}
