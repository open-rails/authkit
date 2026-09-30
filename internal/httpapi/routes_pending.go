package httpapi

import (
	"net/http"

	"github.com/open-rails/authkit/internal/errmodel"
)

// notYet answers the #407 routes whose handlers are still being written.
func notYet(w http.ResponseWriter) { fail(w, errmodel.CodeNotImplemented) }

func (s *Service) handleMePATCH(w http.ResponseWriter, r *http.Request)       { notYet(w) }
func (s *Service) handleMeSecurityGET(w http.ResponseWriter, r *http.Request) { notYet(w) }
func (s *Service) handleMeEmailPUT(w http.ResponseWriter, r *http.Request)    { notYet(w) }
func (s *Service) handleMePhonePUT(w http.ResponseWriter, r *http.Request)    { notYet(w) }
func (s *Service) handleMePhoneDELETE(w http.ResponseWriter, r *http.Request) { notYet(w) }
func (s *Service) handleMeSessionEventsGET(w http.ResponseWriter, r *http.Request) {
	notYet(w)
}
func (s *Service) handleSignInKeysGET(w http.ResponseWriter, r *http.Request)   { notYet(w) }
func (s *Service) handleSignInKeyPATCH(w http.ResponseWriter, r *http.Request)  { notYet(w) }
func (s *Service) handleSignInKeyDELETE(w http.ResponseWriter, r *http.Request) { notYet(w) }
func (s *Service) handleTwoFactorStepUpSendPOST(w http.ResponseWriter, r *http.Request) {
	notYet(w)
}
func (s *Service) handleMe2FASetupPOST(w http.ResponseWriter, r *http.Request)    { notYet(w) }
func (s *Service) handleMe2FAFactorsPOST(w http.ResponseWriter, r *http.Request)  { notYet(w) }
func (s *Service) handleMe2FAFactorPATCH(w http.ResponseWriter, r *http.Request)  { notYet(w) }
func (s *Service) handleMe2FAFactorDELETE(w http.ResponseWriter, r *http.Request) { notYet(w) }
