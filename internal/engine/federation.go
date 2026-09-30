package engine

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/internal/errmodel"
	"github.com/open-rails/authkit/internal/ident"
	"github.com/open-rails/authkit/internal/jose"
	"github.com/open-rails/authkit/verify"
)

// Federation: tokens the stored remote applications issue. Each verification
// reads the application's live row, so disabling or deleting it, or changing
// its keys, takes effect on the next request, and its authority is resolved
// live. Which issuers are applications at all is answered from a snapshot of
// the enabled set, refreshed at most once per federationSnapshotTTL, so a
// made-up iss costs no database read of its own (ak#297). An application
// that leaves the enabled set is removed from the verifier the first time its
// issuer is seen again, and that token is refused (ak#417).

const federationSnapshotTTL = 5 * time.Second

// federation is the engine's snapshot of the enabled applications' issuers,
// shared by its authenticators.
type federation struct {
	mu       sync.Mutex
	enabled  map[string]bool
	at       time.Time
	inflight chan struct{}
}

// federated is the enabled application whose issuer is iss, registered on
// a's verifier; found is false when iss is this deployment's or no
// application's. The issuer of an application registered here that is no
// longer enabled is de-registered and its token refused.
func (a *Authenticator) federated(ctx context.Context, iss string) (iam.RemoteApplication, bool, error) {
	s := a.s
	iss = strings.TrimSpace(iss)
	if s.pg == nil || iss == s.cfg.Token.Issuer || !ident.ValidIssuer(iss) {
		return iam.RemoteApplication{}, false, nil
	}
	if !s.fed.isEnabled(ctx, iss, s.ListEnabledRemoteApplications) {
		if a.unregister(iss) {
			return iam.RemoteApplication{}, false, errmodel.E(errmodel.CodeBadIssuer)
		}
		return iam.RemoteApplication{}, false, nil
	}
	app, err := s.GetRemoteApplication(ctx, iss)
	if err != nil || app == nil || app.Issuer != iss {
		a.unregister(iss)
		return iam.RemoteApplication{}, false, errmodel.E(errmodel.CodeBadIssuer)
	}
	if err := a.register(*app); err != nil {
		return iam.RemoteApplication{}, false, errmodel.E(errmodel.CodeBadIssuer, errmodel.WithCause(err))
	}
	return *app, true, nil
}

// isEnabled answers from the snapshot when it is fresh, otherwise after one
// single-flighted refresh. A failed refresh still stamps the snapshot, so a
// failing store is asked at most once per TTL.
func (f *federation) isEnabled(ctx context.Context, iss string, list func(context.Context) ([]iam.RemoteApplication, error)) bool {
	f.mu.Lock()
	if f.enabled[iss] || time.Since(f.at) < federationSnapshotTTL {
		ok := f.enabled[iss]
		f.mu.Unlock()
		return ok
	}
	if wait := f.inflight; wait != nil {
		f.mu.Unlock()
		// Released by the refresh, the caller's context or the TTL: a stalled
		// store never pins a request past its own deadline.
		select {
		case <-wait:
		case <-ctx.Done():
			return false
		case <-time.After(federationSnapshotTTL):
			return false
		}
		f.mu.Lock()
		defer f.mu.Unlock()
		return f.enabled[iss]
	}
	done := make(chan struct{})
	f.inflight = done
	f.mu.Unlock()

	listCtx, cancel := context.WithTimeout(ctx, federationSnapshotTTL)
	apps, err := list(listCtx)
	cancel()

	f.mu.Lock()
	defer f.mu.Unlock()
	if err == nil {
		f.enabled = make(map[string]bool, len(apps))
		for _, app := range apps {
			if app.Enabled {
				f.enabled[strings.TrimSpace(app.Issuer)] = true
			}
		}
	}
	f.at, f.inflight = time.Now(), nil
	close(done)
	return f.enabled[iss]
}

// register trusts app's current key source on a's verifier, replacing the
// earlier one when it changed: JWKS mode fetches from its URI, static mode
// uses its key list.
func (a *Authenticator) register(app iam.RemoteApplication) error {
	var opts verify.IssuerOptions
	source := string(app.Mode)
	switch app.Mode {
	case iam.RemoteApplicationModeJWKS:
		if opts.JWKSURI = strings.TrimSpace(app.JWKSURI); opts.JWKSURI == "" {
			return errors.New("jwks application without a jwks_uri")
		}
		source += " " + opts.JWKSURI
	case iam.RemoteApplicationModeStatic:
		opts.Keys = app.PublicKeys
		keys, _ := json.Marshal(app.PublicKeys)
		source += " " + string(keys)
	default:
		return errors.New("unknown application trust mode")
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.registered[app.Issuer] == source {
		return nil
	}
	if err := a.v.AddIssuer(app.Issuer, a.audiences, opts); err != nil {
		return err
	}
	if a.registered == nil {
		a.registered = map[string]string{}
	}
	a.registered[app.Issuer] = source
	return nil
}

// unregister removes iss from a's verifier, reporting whether it was an
// application registered there.
func (a *Authenticator) unregister(iss string) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	if _, ok := a.registered[iss]; !ok {
		return false
	}
	a.v.RemoveIssuer(iss)
	delete(a.registered, iss)
	return true
}

// applicationClaims verifies a token app issued: the application acting as
// itself (remote-application-access+jwt), or a delegation it signed. Either
// way its authority is the application's stored grants, which a permissions
// claim may only narrow. An application mints no user tokens.
func (a *Authenticator) applicationClaims(ctx context.Context, app iam.RemoteApplication, token, typ string, r *http.Request, dpop bool) (verify.Claims, error) {
	switch {
	case strings.EqualFold(typ, jose.RemoteApplicationAccessTokenType):
		// The typ was read before verification; VerifyClaims then checks the
		// signature over that same header.
		mc, err := a.v.VerifyClaims(ctx, token)
		if err != nil {
			return verify.Claims{}, err
		}
		if jose.String(mc, "sub") != "" || jose.String(mc, "delegated_sub") != "" {
			return verify.Claims{}, errmodel.E(errmodel.CodeRemoteApplicationAccessHasSubject)
		}
		if member, _, err := jose.Confirmation(token); err != nil {
			return verify.Claims{}, verify.ErrInvalidConfirmation
		} else if member != "" {
			return verify.Claims{}, verify.ErrConfirmationWrongTokenType
		}
		if dpop {
			return verify.Claims{}, verify.ErrSenderProofRequired
		}
		// A present claim narrows, an empty one to nothing; absent is the
		// whole stored authority.
		requested := jose.Strings(mc, "permissions")
		if _, present := mc["permissions"]; present && requested == nil {
			requested = []string{}
		}
		cl := verify.Claims{Kind: iam.ActorRemoteApplication, JOSEType: typ, Issuer: app.Issuer}
		return a.s.withinApplication(ctx, app, cl, requested)
	case strings.EqualFold(typ, jose.DelegatedAccessTokenType):
		var cl verify.Claims
		var err error
		if r != nil {
			cl, err = a.v.VerifyRequest(r)
		} else {
			cl, err = a.v.Verify(ctx, token)
		}
		if err == nil && cl.Kind != iam.ActorDelegated {
			err = errmodel.E(errmodel.CodeNotDelegatedAccessToken)
		}
		if err != nil {
			return verify.Claims{}, err
		}
		// An application's sign-ins are not AuthKit's.
		cl.SessionID, cl.DeviceKeyID = "", ""
		// Its delegation grants only what it names, within the ceiling.
		requested := cl.Permissions
		if requested == nil {
			requested = []string{}
		}
		return a.s.withinApplication(ctx, app, cl, requested)
	}
	return verify.Claims{}, errmodel.E(errmodel.CodeBadIssuer)
}

// withinApplication bounds cl to app's stored authority and binds it to
// the group that authority is held in (#248). requested nil is the whole
// ceiling; a permission outside it refuses the token.
func (s *Engine) withinApplication(ctx context.Context, app iam.RemoteApplication, cl verify.Claims, requested []string) (verify.Claims, error) {
	scope, granted, err := s.storedApplicationAuthority(ctx, app.ID)
	if err != nil {
		return verify.Claims{}, errmodel.E(errmodel.CodeInvalidToken)
	}
	perms := ident.Strings(granted)
	if requested != nil {
		perms = make([]string, 0, len(requested))
		for _, p := range requested {
			if p = strings.TrimSpace(p); p == "" || slices.Contains(perms, p) {
				continue
			}
			if !slices.ContainsFunc(granted, ident.Perm(p).Matches) {
				return verify.Claims{}, errmodel.E(errmodel.CodePermissionNotGranted)
			}
			perms = append(perms, p)
		}
	}
	cl.Permissions = perms
	cl.RemoteApplicationID = app.ID
	cl.Group = &scope
	return cl, nil
}
