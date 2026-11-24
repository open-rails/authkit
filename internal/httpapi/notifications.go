package httpapi

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"

	"github.com/open-rails/authkit/auth"
	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/internal/errmodel"
	"github.com/open-rails/authkit/notify"
	"github.com/open-rails/authkit/verify"
)

// NotificationQuery selects only the authenticated account's receipts.
type NotificationQuery struct {
	Limit     *int   `query:"limit"`
	Cursor    string `query:"cursor"`
	Unread    bool   `query:"unread"`
	Dismissed bool   `query:"dismissed"`
}

type NotificationMutations struct {
	Mutations []notify.Mutation `json:"mutations"`
}

func (s *Service) notificationUser(w http.ResponseWriter, r *http.Request) (string, bool) {
	c, ok := verify.ClaimsFromContext(r.Context())
	if !ok || !c.IsUser() {
		s.fail(w, errmodel.CodeUnauthenticated)
		return "", false
	}
	return c.UserID, true
}

func (s *Service) notificationError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, notify.ErrNotFound), errors.Is(err, iam.ErrUserNotFound):
		s.fail(w, errmodel.CodeNotFound)
	case errors.Is(err, notify.ErrInvalid):
		s.fail(w, errmodel.CodeInvalidRequest)
	case errors.Is(err, notify.ErrConflict):
		s.fail(w, errmodel.CodeNotificationConflict)
	case errors.Is(err, auth.ErrForbidden):
		s.fail(w, errmodel.CodeForbidden)
	default:
		s.writeError(w, err)
	}
}

func (s *Service) handleNotificationsList(w http.ResponseWriter, r *http.Request) {
	user, ok := s.notificationUser(w, r)
	if !ok {
		return
	}
	var q NotificationQuery
	if !s.readQuery(w, r, &q) {
		return
	}
	opts := notify.ListOptions{Cursor: q.Cursor, UnreadOnly: q.Unread, Dismissed: q.Dismissed}
	if q.Limit != nil {
		if *q.Limit < 1 || *q.Limit > 100 {
			s.fail(w, errmodel.CodeInvalidRequest)
			return
		}
		opts.Limit = *q.Limit
	}
	out, err := s.svc.ListNotifications(r.Context(), user, opts)
	if err != nil {
		s.notificationError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, out)
}
func (s *Service) handleNotificationGet(w http.ResponseWriter, r *http.Request) {
	user, ok := s.notificationUser(w, r)
	if !ok {
		return
	}
	out, err := s.svc.GetNotification(r.Context(), user, r.PathValue("notification_id"))
	if err != nil {
		s.notificationError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, out)
}
func (s *Service) handleNotificationRead(w http.ResponseWriter, r *http.Request) {
	user, ok := s.notificationUser(w, r)
	if !ok {
		return
	}
	out, err := s.svc.SetNotificationRead(r.Context(), user, r.PathValue("notification_id"), r.Method == http.MethodPut)
	if err != nil {
		s.notificationError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, out)
}
func (s *Service) handleNotificationDismiss(w http.ResponseWriter, r *http.Request) {
	user, ok := s.notificationUser(w, r)
	if !ok {
		return
	}
	out, err := s.svc.SetNotificationDismissed(r.Context(), user, r.PathValue("notification_id"), r.Method == http.MethodPut)
	if err != nil {
		s.notificationError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, out)
}
func (s *Service) handleNotificationsApply(w http.ResponseWriter, r *http.Request) {
	who, ok := verify.IdentityFromContext(r.Context())
	if !ok {
		s.fail(w, errmodel.CodeUnauthenticated)
		return
	}
	name := r.PathValue("producer")
	if err := s.svc.AuthorizeNotifications(r.Context(), who, name); err != nil {
		s.notificationError(w, err)
		return
	}
	// A bounded producer batch can contain 100 payloads of 64 KiB each; the
	// ordinary authentication body limit is intentionally smaller.
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 8<<20))
	dec.DisallowUnknownFields()
	var in NotificationMutations
	if err := dec.Decode(&in); err != nil {
		s.fail(w, errmodel.CodeInvalidRequest)
		return
	}
	if err := dec.Decode(&struct{}{}); err != io.EOF {
		s.fail(w, errmodel.CodeInvalidRequest)
		return
	}
	// Reading a bounded producer body can still outlive a credential or role.
	// Recheck current authority immediately before accepting its effects.
	if err := s.svc.AuthorizeNotifications(r.Context(), who, name); err != nil {
		s.notificationError(w, err)
		return
	}
	if err := s.svc.ApplyNotifications(r.Context(), name, in.Mutations); err != nil {
		s.notificationError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
