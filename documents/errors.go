package documents

import "github.com/open-rails/authkit/iam"

// Document error sentinels on the one AuthKit error model (ak#290); their
// codes live in the iam catalog.
var (
	ErrInvalidReference     = iam.E(iam.CodeInvalidDocumentReference)
	ErrInvalidType          = iam.E(iam.CodeInvalidDocumentType)
	ErrInvalidDigest        = iam.E(iam.CodeInvalidDocumentDigest)
	ErrDuplicateReference   = iam.E(iam.CodeDuplicateDocumentReference)
	ErrTooManyReferences    = iam.E(iam.CodeTooManyDocumentReferences)
	ErrReferencesTooLarge   = iam.E(iam.CodeDocumentReferencesTooLarge)
	ErrWrongTokenType       = iam.E(iam.CodeDocumentsWrongTokenType)
	ErrReservedAttribute    = iam.E(iam.CodeReservedDocumentAttribute)
	ErrInvalidEnvelope      = iam.E(iam.CodeInvalidDocumentEnvelope)
	ErrPayloadTooLarge      = iam.E(iam.CodeDocumentPayloadTooLarge)
	ErrMalformedJWS         = iam.E(iam.CodeMalformedDocumentJWS)
	ErrWrongJOSEType        = iam.E(iam.CodeWrongDocumentJOSEType)
	ErrUnsupportedAlgorithm = iam.E(iam.CodeUnsupportedDocumentAlgorithm)
	ErrUnsupportedSigner    = iam.E(iam.CodeUnsupportedDocumentSigner)
	ErrUnknownKey           = iam.E(iam.CodeUnknownDocumentKey)
	ErrInvalidSignature     = iam.E(iam.CodeInvalidDocumentSignature)
	ErrDigestMismatch       = iam.E(iam.CodeDocumentDigestMismatch)
	ErrIssuerMismatch       = iam.E(iam.CodeDocumentIssuerMismatch)
	ErrAudienceMismatch     = iam.E(iam.CodeDocumentAudienceMismatch)
	ErrTypeMismatch         = iam.E(iam.CodeDocumentTypeMismatch)
	ErrUntrustedIssuer      = iam.E(iam.CodeUntrustedDocumentIssuer)
	ErrUnauthorized         = iam.E(iam.CodeDocumentUnauthorized)
	ErrNotFound             = iam.E(iam.CodeDocumentNotFound)
	ErrFetch                = iam.E(iam.CodeDocumentFetchFailed)
	ErrRedirect             = iam.E(iam.CodeDocumentRedirectRejected)
	ErrDigestCollision      = iam.E(iam.CodeDocumentDigestCollision)
)
