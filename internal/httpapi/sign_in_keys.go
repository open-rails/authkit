package httpapi

import (
	"cmp"
	"errors"
	"net/http"
	"slices"
	"strings"

	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/internal/errmodel"
	"github.com/open-rails/authkit/verify"
)

// The caller's sign-in keys: passkeys and device keys in one view, each
// managed by its own protocol's engine calls. Any session of the caller
// (browser or device key) reaches them.

// maxSignInKeyLabel bounds a key's label.
const maxSignInKeyLabel = 128

func (s *Service) handleSignInKeysGET(w http.ResponseWriter, r *http.Request) {
	claims, ok := verify.ClaimsFromContext(r.Context())
	if !ok || claims.UserID == "" {
		fail(w, errmodel.CodeUnauthenticated)
		return
	}
	keys := []SignInKey{}
	if s.svc.PasskeysEnabled() {
		passkeys, err := s.svc.ListPasskeys(r.Context(), claims.UserID)
		if err != nil {
			serverErr(w, "list_passkeys", err)
			return
		}
		for _, p := range passkeys {
			keys = append(keys, passkeySignInKey(p))
		}
	}
	if s.cfg.DeviceKeys.Enabled {
		deviceKeys, err := s.svc.DeviceKeys(r.Context(), claims.UserID)
		if err != nil {
			serverErr(w, "list_device_keys", err)
			return
		}
		for _, k := range deviceKeys {
			if k.RevokedAt == nil {
				keys = append(keys, deviceSignInKey(k, claims))
			}
		}
	}
	slices.SortStableFunc(keys, func(a, b SignInKey) int {
		return cmp.Or(a.CreatedAt.Compare(b.CreatedAt), cmp.Compare(a.ID, b.ID))
	})
	all(w, keys)
}

// handleSignInKeyPATCH relabels one of the caller's passkeys or live device
// keys (an empty label clears it).
func (s *Service) handleSignInKeyPATCH(w http.ResponseWriter, r *http.Request) {
	claims, ok := verify.ClaimsFromContext(r.Context())
	if !ok || claims.UserID == "" {
		fail(w, errmodel.CodeUnauthenticated)
		return
	}
	var req LabelRequest
	if err := decodeJSON(r, &req); err != nil {
		fail(w, errmodel.CodeInvalidRequest)
		return
	}
	label := strings.TrimSpace(req.Label)
	if len(label) > maxSignInKeyLabel {
		fail(w, errmodel.CodeInvalidRequest, errmodel.WithParam("label"))
		return
	}
	id := strings.TrimSpace(r.PathValue("id"))
	if s.svc.PasskeysEnabled() {
		err := s.svc.RenamePasskey(r.Context(), claims.UserID, id, label)
		if err == nil {
			s.writePasskeySignInKey(w, r, claims.UserID, id)
			return
		}
		if !errors.Is(err, errmodel.ErrPasskeyNotFound) {
			writeError(w, err)
			return
		}
	}
	if s.cfg.DeviceKeys.Enabled {
		key, err := s.svc.RelabelDeviceKey(r.Context(), claims.UserID, id, label)
		if err == nil {
			writeJSON(w, http.StatusOK, deviceSignInKey(key, claims))
			return
		}
		if errmodel.CodeOf(err) != errmodel.CodeNotFound {
			writeError(w, err)
			return
		}
	}
	fail(w, errmodel.CodeNotFound)
}

// handleSignInKeyDELETE deletes one of the caller's passkeys or revokes one of
// its device keys; a revoked key stays revoked, and an unknown one is 404.
func (s *Service) handleSignInKeyDELETE(w http.ResponseWriter, r *http.Request) {
	claims, ok := verify.ClaimsFromContext(r.Context())
	if !ok || claims.UserID == "" {
		fail(w, errmodel.CodeUnauthenticated)
		return
	}
	id := strings.TrimSpace(r.PathValue("id"))
	if s.svc.PasskeysEnabled() {
		err := s.svc.DeletePasskey(r.Context(), claims.UserID, id)
		if err == nil {
			noContent(w)
			return
		}
		if !errors.Is(err, errmodel.ErrPasskeyNotFound) {
			writeError(w, err)
			return
		}
	}
	if s.cfg.DeviceKeys.Enabled {
		err := s.svc.RevokeDeviceKey(r.Context(), claims.UserID, claims.DeviceKeyID, id)
		if err == nil {
			noContent(w)
			return
		}
		if errmodel.CodeOf(err) != errmodel.CodeNotFound {
			writeError(w, err)
			return
		}
	}
	fail(w, errmodel.CodeNotFound)
}

// handlePasskeyRegisterBeginPOST starts adding a passkey: a new way to sign
// in, so the caller needs a proven contact and a recent sign-in.
func (s *Service) handlePasskeyRegisterBeginPOST(w http.ResponseWriter, r *http.Request) {
	claims, ok := s.newSignInMethodCaller(w, r)
	if !ok {
		return
	}
	creation, err := s.svc.BeginPasskeyRegistration(r.Context(), claims.UserID)
	if err != nil {
		serverErr(w, "passkey_failed", err)
		return
	}
	writeJSON(w, http.StatusOK, creation)
}

func (s *Service) handlePasskeyRegisterFinishPOST(w http.ResponseWriter, r *http.Request) {
	claims, ok := s.newSignInMethodCaller(w, r)
	if !ok {
		return
	}
	body, err := readSmallBody(r)
	if err != nil {
		fail(w, errmodel.CodeInvalidRequest)
		return
	}
	passkey, err := s.svc.FinishPasskeyRegistration(r.Context(), claims.UserID, body)
	if err != nil {
		fail(w, errmodel.CodeInvalidRequest)
		return
	}
	writeJSON(w, http.StatusCreated, passkeySignInKey(passkey))
}

// handleDeviceKeysDELETE revokes every device key of the caller but the one
// behind its token: the recovery a new key's email-proven enrollment token
// may run.
func (s *Service) handleDeviceKeysDELETE(w http.ResponseWriter, r *http.Request) {
	claims, ok := verify.ClaimsFromContext(r.Context())
	if !ok || claims.UserID == "" {
		fail(w, errmodel.CodeUnauthenticated)
		return
	}
	// The enrollment finish token is the bounded recovery-root proof: it
	// carries both the device-key and verified-email authentication methods.
	if claims.DeviceKeyID == "" || !claims.HasAMR("device_key") || !claims.HasAMR("email") {
		fail(w, errmodel.CodeForbidden)
		return
	}
	if err := s.svc.RevokeOtherDeviceKeys(r.Context(), claims.UserID, claims.DeviceKeyID); err != nil {
		writeError(w, err)
		return
	}
	noContent(w)
}

// newSignInMethodCaller is the caller of a route that adds a way to sign in:
// its addresses are not all unproven, and it signed in recently.
func (s *Service) newSignInMethodCaller(w http.ResponseWriter, r *http.Request) (verify.Claims, bool) {
	claims, ok := verify.ClaimsFromContext(r.Context())
	if !ok || claims.UserID == "" {
		fail(w, errmodel.CodeUnauthenticated)
		return claims, false
	}
	if !s.requireProvenContact(w, r, claims.UserID) {
		return claims, false
	}
	if err := s.svc.CheckRecentSignIn(r.Context(), claims); err != nil {
		writeError(w, err)
		return claims, false
	}
	return claims, true
}

func (s *Service) writePasskeySignInKey(w http.ResponseWriter, r *http.Request, userID, id string) {
	passkeys, err := s.svc.ListPasskeys(r.Context(), userID)
	if err != nil {
		serverErr(w, "list_passkeys", err)
		return
	}
	for _, p := range passkeys {
		if p.ID == id {
			writeJSON(w, http.StatusOK, passkeySignInKey(p))
			return
		}
	}
	fail(w, errmodel.CodeNotFound)
}

func passkeySignInKey(p iam.Passkey) SignInKey {
	return SignInKey{ID: p.ID, Kind: SignInKeyPasskey, Label: p.Label, CreatedAt: p.CreatedAt, LastUsedAt: p.LastUsedAt}
}

func deviceSignInKey(k iam.DeviceKey, claims verify.Claims) SignInKey {
	return SignInKey{ID: k.ID, Kind: SignInKeyDeviceKey, Label: k.Label, CreatedAt: k.CreatedAt, LastUsedAt: k.LastUsedAt,
		Current: claims.DeviceKeyID != "" && k.ID == claims.DeviceKeyID}
}
