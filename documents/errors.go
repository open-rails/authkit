package documents

import "github.com/open-rails/authkit/internal/errmodel"

// Document error sentinels on the one AuthKit error model (ak#290); their
// codes live in the iam catalog.
var (
	ErrInvalidReference     = errmodel.E(errmodel.CodeInvalidDocumentReference)
	ErrInvalidType          = errmodel.E(errmodel.CodeInvalidDocumentType)
	ErrInvalidDigest        = errmodel.E(errmodel.CodeInvalidDocumentDigest)
	ErrDuplicateReference   = errmodel.E(errmodel.CodeDuplicateDocumentReference)
	ErrTooManyReferences    = errmodel.E(errmodel.CodeTooManyDocumentReferences)
	ErrReferencesTooLarge   = errmodel.E(errmodel.CodeDocumentReferencesTooLarge)
	ErrWrongTokenType       = errmodel.E(errmodel.CodeDocumentsWrongTokenType)
	ErrReservedAttribute    = errmodel.E(errmodel.CodeReservedDocumentAttribute)
	ErrInvalidEnvelope      = errmodel.E(errmodel.CodeInvalidDocumentEnvelope)
	ErrPayloadTooLarge      = errmodel.E(errmodel.CodeDocumentPayloadTooLarge)
	ErrMalformedJWS         = errmodel.E(errmodel.CodeMalformedDocumentJWS)
	ErrWrongJOSEType        = errmodel.E(errmodel.CodeWrongDocumentJOSEType)
	ErrUnsupportedAlgorithm = errmodel.E(errmodel.CodeUnsupportedDocumentAlgorithm)
	ErrUnsupportedSigner    = errmodel.E(errmodel.CodeUnsupportedDocumentSigner)
	ErrUnknownKey           = errmodel.E(errmodel.CodeUnknownDocumentKey)
	ErrInvalidSignature     = errmodel.E(errmodel.CodeInvalidDocumentSignature)
	ErrDigestMismatch       = errmodel.E(errmodel.CodeDocumentDigestMismatch)
	ErrIssuerMismatch       = errmodel.E(errmodel.CodeDocumentIssuerMismatch)
	ErrAudienceMismatch     = errmodel.E(errmodel.CodeDocumentAudienceMismatch)
	ErrTypeMismatch         = errmodel.E(errmodel.CodeDocumentTypeMismatch)
	ErrUntrustedIssuer      = errmodel.E(errmodel.CodeUntrustedDocumentIssuer)
	ErrUnauthorized         = errmodel.E(errmodel.CodeDocumentUnauthorized)
	ErrNotFound             = errmodel.E(errmodel.CodeDocumentNotFound)
	ErrFetch                = errmodel.E(errmodel.CodeDocumentFetchFailed)
	ErrRedirect             = errmodel.E(errmodel.CodeDocumentRedirectRejected)
	ErrDigestCollision      = errmodel.E(errmodel.CodeDocumentDigestCollision)
)
