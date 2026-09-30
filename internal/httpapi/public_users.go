package httpapi

import (
	"errors"
	"net/http"
	"strings"

	"github.com/google/uuid"

	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/internal/errmodel"
)

// maxPublicUserIDs bounds GET /users?ids=.
const maxPublicUserIDs = 100

// handleUsersGET shows anyone, signed in or not, other people as anyone may
// see them (iam.PublicUser: never a contact, ban or sign-in data), by ?ids= (comma
// separated, at most 100; answered in request order, unknown ids absent,
// deleted accounts as tombstones) or by ?username= (a former name resolves
// too; no one is an empty page). Exactly one of the two.
func (s *Service) handleUsersGET(w http.ResponseWriter, r *http.Request) {
	var q UsersQuery
	if !readQuery(w, r, &q) {
		return
	}
	switch {
	case (q.IDs == "") == (q.Username == ""):
		fail(w, errmodel.CodeInvalidRequest)
	case q.Username != "":
		s.publicUserByName(w, r, q.Username)
	default:
		s.publicUsersByID(w, r, q.IDs)
	}
}

func (s *Service) publicUsersByID(w http.ResponseWriter, r *http.Request, text string) {
	var ids []string
	seen := map[string]bool{}
	for _, id := range strings.Split(text, ",") {
		id = strings.TrimSpace(id)
		if id == "" {
			fail(w, errmodel.CodeInvalidRequest, errmodel.WithParam("ids"))
			return
		}
		if u, err := uuid.Parse(id); err == nil {
			id = u.String() // the form the store answers with
		}
		if !seen[id] {
			seen[id] = true
			ids = append(ids, id)
		}
	}
	if len(ids) > maxPublicUserIDs {
		fail(w, errmodel.CodeInvalidRequest, errmodel.WithParam("ids"))
		return
	}
	found, err := s.svc.PublicUsers(r.Context(), ids)
	if err != nil {
		writeError(w, err)
		return
	}
	out := make([]iam.PublicUser, 0, len(found))
	for _, id := range ids {
		if u, ok := found[id]; ok {
			out = append(out, u)
		}
	}
	all(w, out)
}

func (s *Service) publicUserByName(w http.ResponseWriter, r *http.Request, name string) {
	res, err := s.svc.ResolveUsername(r.Context(), name)
	if errors.Is(err, iam.ErrUserNotFound) {
		all(w, []iam.PublicUser{})
		return
	}
	if err != nil {
		writeError(w, err)
		return
	}
	s.publicUsersByID(w, r, res.ID)
}
