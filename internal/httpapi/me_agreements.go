package httpapi

import (
	"net/http"

	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/internal/errmodel"
	"github.com/open-rails/authkit/verify"
)

// GET/POST /me/agreements: the caller's acceptances of Config.Agreements,
// and accepting documents from the account (an existing user, a sign-in's
// agreements_due, an OAuth client's approval).

func (s *Service) handleMeAgreementsGET(w http.ResponseWriter, r *http.Request) {
	claims, ok := verify.ClaimsFromContext(r.Context())
	if !ok || claims.UserID == "" {
		fail(w, errmodel.CodeUnauthenticated)
		return
	}
	s.writeUserAgreements(w, r, claims.UserID)
}

func (s *Service) handleMeAgreementsPOST(w http.ResponseWriter, r *http.Request) {
	claims, ok := verify.ClaimsFromContext(r.Context())
	if !ok || claims.UserID == "" {
		fail(w, errmodel.CodeUnauthenticated)
		return
	}
	var req AgreementsRequest
	if err := decodeJSON(r, &req); err != nil {
		fail(w, errmodel.CodeInvalidRequest)
		return
	}
	if err := s.svc.RecordAgreements(r.Context(), claims.UserID, req.Agreements, iam.AgreementInAccount, s.requestIP(r), r.UserAgent()); err != nil {
		writeError(w, err)
		return
	}
	s.writeUserAgreements(w, r, claims.UserID)
}

func (s *Service) writeUserAgreements(w http.ResponseWriter, r *http.Request, userID string) {
	accepted, err := s.svc.UserAgreements(r.Context(), userID)
	if err != nil {
		writeError(w, err)
		return
	}
	due, err := s.svc.AgreementsDue(r.Context(), userID)
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, UserAgreements{Accepted: accepted, Due: due})
}
