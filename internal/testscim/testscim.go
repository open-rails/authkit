// Package testscim is a SCIM 2.0 service provider for AuthKit's provisioning
// tests: users in memory, every request recorded, failures on demand.
package testscim

import (
	"encoding/json"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync"

	"github.com/open-rails/authkit/internal/scim"
)

// Request is one request the server answered.
type Request struct {
	Method, Path string
	Body         []byte
}

// Server holds users by the id it gives them. Token, when set, is the bearer
// token it requires.
type Server struct {
	Token string

	mu       sync.Mutex
	bulk     bool
	maxOps   int
	users    map[string]scim.User
	next     int
	requests []Request
	failing  int
}

// New is a server; bulk advertises and serves /Bulk with maxOps operations
// per request.
func New(bulk bool, maxOps int) *Server {
	return &Server{bulk: bulk, maxOps: maxOps, users: map[string]scim.User{}}
}

// FailNext answers the next n requests 503.
func (s *Server) FailNext(n int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.failing = n
}

// Requests are the requests answered so far.
func (s *Server) Requests() []Request {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]Request(nil), s.requests...)
}

// User is the user whose externalId is id.
func (s *Server) User(id string) (scim.User, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, u := range s.users {
		if u.ExternalID == id {
			return u, true
		}
	}
	return scim.User{}, false
}

// Len is how many users the server holds.
func (s *Server) Len() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.users)
}

// Edit changes the user whose externalId is id behind AuthKit's back.
func (s *Server) Edit(id string, edit func(*scim.User)) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for key, u := range s.users {
		if u.ExternalID == id {
			edit(&u)
			s.users[key] = u
		}
	}
}

// Remove deletes the user whose externalId is id behind AuthKit's back.
func (s *Server) Remove(id string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for key, u := range s.users {
		if u.ExternalID == id {
			delete(s.users, key)
		}
	}
}

// Add stores u as if another client had created it.
func (s *Server) Add(u scim.User) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.create(u)
}

func (s *Server) create(u scim.User) string {
	s.next++
	u.ID = "r-" + strconv.Itoa(s.next)
	s.users[u.ID] = u
	return u.ID
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	s.mu.Lock()
	defer s.mu.Unlock()
	s.requests = append(s.requests, Request{Method: r.Method, Path: r.URL.Path, Body: body})
	if s.Token != "" && r.Header.Get("Authorization") != "Bearer "+s.Token {
		write(w, http.StatusUnauthorized, scim.NewError(http.StatusUnauthorized, "", "bad token"))
		return
	}
	if s.failing > 0 {
		s.failing--
		write(w, http.StatusServiceUnavailable, scim.NewError(http.StatusServiceUnavailable, "", "try later"))
		return
	}
	path := strings.TrimPrefix(r.URL.Path, "/scim/v2")
	switch {
	case r.Method == http.MethodGet && path == "/ServiceProviderConfig":
		write(w, http.StatusOK, scim.ServiceProviderConfig{
			Schemas: []string{scim.SchemaServiceProviderConfig},
			Bulk:    scim.BulkSupport{Supported: s.bulk, MaxOperations: s.maxOps, MaxPayloadSize: 1 << 20},
			Filter:  scim.FilterSupport{Supported: true, MaxResults: 50},
		})
	case r.Method == http.MethodPost && path == "/Bulk" && s.bulk:
		var req scim.BulkRequest
		if err := json.Unmarshal(body, &req); err != nil || len(req.Operations) > s.maxOps {
			write(w, http.StatusBadRequest, scim.NewError(http.StatusBadRequest, "invalidSyntax", "bad bulk request"))
			return
		}
		resp := scim.BulkResponse{Schemas: []string{scim.SchemaBulkResponse}}
		for _, op := range req.Operations {
			data, _ := json.Marshal(op.Data)
			status, location, errBody := s.apply(op.Method, op.Path, data)
			res := scim.BulkResult{Method: op.Method, BulkID: op.BulkID, Location: location, Status: scim.Status(status)}
			if errBody != nil {
				res.Response, _ = json.Marshal(errBody)
			}
			resp.Operations = append(resp.Operations, res)
		}
		write(w, http.StatusOK, resp)
	case r.Method == http.MethodGet && path == "/Users":
		s.list(w, r)
	default:
		status, location, errBody := s.apply(r.Method, path, body)
		if errBody != nil {
			write(w, status, errBody)
			return
		}
		if location != "" {
			w.Header().Set("Location", location)
		}
		if r.Method == http.MethodDelete {
			w.WriteHeader(status)
			return
		}
		write(w, status, s.users[scim.LocationID(location)])
	}
}

// apply runs one write and returns its status, the resource's location and
// an error body.
func (s *Server) apply(method, path string, body []byte) (int, string, *scim.Error) {
	fail := func(status int, scimType string) (int, string, *scim.Error) {
		e := scim.NewError(status, scimType, http.StatusText(status))
		return status, "", &e
	}
	id, item := strings.CutPrefix(path, "/Users/")
	var u scim.User
	if method == http.MethodPost || method == http.MethodPut {
		if err := json.Unmarshal(body, &u); err != nil || u.UserName == "" {
			return fail(http.StatusBadRequest, "invalidValue")
		}
		for key, other := range s.users {
			if key != id && (other.ExternalID == u.ExternalID || strings.EqualFold(other.UserName, u.UserName)) {
				return fail(http.StatusConflict, "uniqueness")
			}
		}
	}
	switch {
	case method == http.MethodPost && path == "/Users":
		return http.StatusCreated, "/scim/v2/Users/" + s.create(u), nil
	case !item:
		return fail(http.StatusNotFound, "")
	case method == http.MethodPut:
		if _, ok := s.users[id]; !ok {
			return fail(http.StatusNotFound, "")
		}
		u.ID = id
		s.users[id] = u
		return http.StatusOK, "/scim/v2/Users/" + id, nil
	case method == http.MethodDelete:
		if _, ok := s.users[id]; !ok {
			return fail(http.StatusNotFound, "")
		}
		delete(s.users, id)
		return http.StatusNoContent, "", nil
	}
	return fail(http.StatusMethodNotAllowed, "")
}

func (s *Server) list(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	var all []scim.User
	for _, u := range s.users {
		all = append(all, u)
	}
	if f := q.Get("filter"); f != "" {
		attr, value, _ := strings.Cut(f, " eq ")
		value, _ = strconv.Unquote(value)
		var out []scim.User
		for _, u := range all {
			if attr == "externalId" && u.ExternalID == value {
				out = append(out, u)
			}
		}
		all = out
	}
	// Stable pages: by id.
	for i := range all {
		for j := i + 1; j < len(all); j++ {
			if all[j].ID < all[i].ID {
				all[i], all[j] = all[j], all[i]
			}
		}
	}
	start, _ := strconv.Atoi(q.Get("startIndex"))
	count, err := strconv.Atoi(q.Get("count"))
	if err != nil {
		count = len(all)
	}
	start = min(max(start, 1), len(all)+1)
	page := all[start-1 : min(start-1+count, len(all))]
	write(w, http.StatusOK, scim.ListResponse[scim.User]{
		Schemas: []string{scim.SchemaListResponse}, TotalResults: len(all), StartIndex: start, ItemsPerPage: len(page), Resources: page,
	})
}

func write(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", scim.MediaType)
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
