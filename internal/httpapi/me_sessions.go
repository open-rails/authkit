package httpapi

import (
	"net/http"
	"slices"
	"strings"

	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/internal/authflow"
	"github.com/open-rails/authkit/internal/errmodel"
)

// The caller's sessions on this issuer and its session history.

func (s *Service) handleMeSessionsGET(w http.ResponseWriter, r *http.Request) {
	cl, err := callerClaims(r)
	if err != nil || strings.TrimSpace(cl.UserID) == "" {
		fail(w, errmodel.CodeUnauthenticated)
		return
	}
	sessions, err := s.svc.Sessions(r.Context(), cl.UserID)
	if err != nil {
		serverErr(w, "failed_to_list", err)
		return
	}
	for i := range sessions {
		sessions[i].Current = sessions[i].ID == cl.SessionID
	}
	all(w, sessions)
}

// handleMeSessionDELETE signs out one session; an unknown or ended session is
// already signed out.
func (s *Service) handleMeSessionDELETE(w http.ResponseWriter, r *http.Request) {
	cl, err := callerClaims(r)
	if err != nil || strings.TrimSpace(cl.UserID) == "" {
		fail(w, errmodel.CodeUnauthenticated)
		return
	}
	sid := strings.TrimSpace(r.PathValue("id"))
	if sid == "" {
		fail(w, errmodel.CodeMissingSessionID)
		return
	}
	ctx := authflow.WithSessionRevokeReason(r.Context(), authflow.SessionRevokeReasonUserRevoke)
	if err := s.svc.RevokeSessionByIDForUser(ctx, cl.UserID, sid); err != nil {
		serverErr(w, "failed_to_revoke", err)
		return
	}
	noContent(w)
}

// handleMeSessionsDELETE signs out every other session and keeps the
// caller's; device keys stay (DELETE /logout ends the caller's own sign-in).
func (s *Service) handleMeSessionsDELETE(w http.ResponseWriter, r *http.Request) {
	cl, err := callerClaims(r)
	if err != nil || strings.TrimSpace(cl.UserID) == "" {
		fail(w, errmodel.CodeUnauthenticated)
		return
	}
	var keep *string
	if cl.SessionID != "" {
		keep = &cl.SessionID
	}
	ctx := authflow.WithSessionRevokeReason(r.Context(), authflow.SessionRevokeReasonUserRevokeAll)
	if err := s.svc.RevokeIssuerSessions(ctx, cl.UserID, keep); err != nil {
		serverErr(w, "failed_to_revoke_all", err)
		return
	}
	noContent(w)
}

// handleMeSessionEventsGET pages the caller's session history, newest first
// (?kind= repeats; every kind when absent).
func (s *Service) handleMeSessionEventsGET(w http.ResponseWriter, r *http.Request) {
	cl, err := callerClaims(r)
	if err != nil || strings.TrimSpace(cl.UserID) == "" {
		fail(w, errmodel.CodeUnauthenticated)
		return
	}
	q, ok := readSessionEventQuery(w, r)
	if !ok {
		return
	}
	page, err := s.svc.ListSessionEvents(r.Context(), cl.UserID, q)
	if err != nil {
		writeError(w, err)
		return
	}
	list(w, page)
}

// sessionEventKinds are the kinds ?kind= may name.
var sessionEventKinds = []iam.SessionEventKind{
	iam.SessionEventCreated, iam.SessionEventFailed, iam.SessionEventRevoked,
	iam.SessionEventPasswordChange, iam.SessionEventPasswordRecovery, iam.SessionEventAccountSessionsRevoked,
}

// readSessionEventQuery reads a session history's ?kind=, ?cursor= and
// ?limit=, answering 400 for an unknown kind or a bad limit.
func readSessionEventQuery(w http.ResponseWriter, r *http.Request) (iam.SessionEventQuery, bool) {
	var query SessionEventQuery
	if !readQuery(w, r, &query) {
		return iam.SessionEventQuery{}, false
	}
	page, err := query.Page()
	if err != nil {
		writeError(w, err)
		return iam.SessionEventQuery{}, false
	}
	q := iam.SessionEventQuery{Page: page}
	for _, k := range query.Kind {
		kind := iam.SessionEventKind(k)
		if !slices.Contains(sessionEventKinds, kind) {
			fail(w, errmodel.CodeInvalidRequest, errmodel.WithParam("kind"))
			return iam.SessionEventQuery{}, false
		}
		q.Kinds = append(q.Kinds, kind)
	}
	return q, true
}
