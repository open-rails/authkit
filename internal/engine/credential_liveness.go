package engine

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/open-rails/authkit/auth"
	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/internal/errmodel"
	"github.com/open-rails/authkit/verify"
)

// CheckCredential is a trusted-claims native liveness operation, distinct from
// permission evaluation and from CheckSession's existing admission behavior.
func (s *Engine) CheckCredential(ctx context.Context, cl verify.Claims) error {
	if cl.Kind != verify.TokenUser {
		return errmodel.E(errmodel.CodeForbidden)
	}
	if err := s.CheckSession(ctx, cl); err != nil {
		return err
	}
	if cl.Group != nil {
		group, err := s.groupStore().groupByID(ctx, cl.Group.GroupID)
		switch {
		case errors.Is(err, iam.ErrGroupNotFound):
			return iam.ErrSessionRevoked
		case err != nil:
			return err
		case group.DeletedAt != nil:
			return iam.ErrSessionRevoked
		}
	}
	if !cl.ValidUntil.IsZero() && time.Now().After(cl.ValidUntil) {
		return iam.ErrTokenExpired
	}
	return nil
}

// CheckCredential reads the registration that originally established resource
// identity. It never refreshes keys, revalidates the signature or sender proof,
// changes the retained identity, or promotes it to native IAM authority.
func (v resourceVerified) CheckCredential(ctx context.Context) error {
	cl := v.access.Claims
	if cl.Kind != verify.TokenUser || v.s.resource == nil {
		return auth.ErrForbidden
	}
	if err := resourceCredentialExpiry(cl); err != nil {
		return err
	}
	if previous := v.access.Application; previous != nil {
		current, err := v.s.GetRemoteApplication(ctx, previous.Issuer)
		if err != nil {
			return resourceCredentialFailure(err)
		}
		if current.ID != previous.ID || current.GroupID != previous.GroupID || current.Issuer != previous.Issuer {
			return errors.Join(auth.ErrUnauthenticated, auth.ErrRevoked)
		}
		_, owner, err := v.s.remoteDirectoryContext(ctx, current.GroupID)
		if err != nil {
			return resourceCredentialFailure(err)
		}
		if owner.IsZero() && v.id.TenantID != "" || !owner.IsZero() && owner.String() != v.id.TenantID {
			return errors.Join(auth.ErrUnauthenticated, auth.ErrRevoked)
		}
	} else {
		// Reuse current OAuth client/session and exchanged-group validation.
		// Do not adopt a different application or group after configuration edits.
		client, exists, err := v.s.OAuthClient(ctx, cl.ClientID)
		if err != nil {
			return resourceCredentialFailure(err)
		}
		if !exists {
			return errors.Join(auth.ErrUnauthenticated, auth.ErrRevoked)
		}
		group := ""
		if client.Group != nil {
			group = client.Group.GroupID
		}
		if group != v.access.ClientGroup {
			return errors.Join(auth.ErrUnauthenticated, auth.ErrRevoked)
		}
		if err := v.s.resource.userTokenStands(ctx, cl); err != nil {
			return resourceCredentialFailure(err)
		}
		exchanged, err := v.s.resource.exchangedGroup(ctx, ResourceAccess{ClientGroup: group}, cl)
		if err != nil {
			return resourceCredentialFailure(err)
		}
		if exchanged != v.access.ExchangedGroup {
			return errors.Join(auth.ErrUnauthenticated, auth.ErrRevoked)
		}
		owner, err := v.s.credentialTenant(ctx, v.s.q, cl.Subject, cl.TenantID)
		if err != nil {
			return resourceCredentialFailure(err)
		}
		if owner.String() != v.id.TenantID {
			return errors.Join(auth.ErrUnauthenticated, auth.ErrRevoked)
		}
	}
	return resourceCredentialExpiry(cl)
}

func resourceCredentialExpiry(cl verify.Claims) error {
	if !cl.ValidUntil.IsZero() && time.Now().After(cl.ValidUntil) {
		return errors.Join(auth.ErrUnauthenticated, auth.ErrExpired, iam.ErrTokenExpired)
	}
	return nil
}

func resourceCredentialFailure(err error) error {
	switch {
	case errors.Is(err, iam.ErrTokenExpired):
		return errors.Join(auth.ErrUnauthenticated, auth.ErrExpired, err)
	case errors.Is(err, iam.ErrSessionRevoked), errors.Is(err, iam.ErrRemoteApplicationNotFound),
		errors.Is(err, iam.ErrInvalidRemoteApplication), errors.Is(err, iam.ErrGroupNotFound),
		errors.Is(err, iam.ErrTenantMismatch), errors.Is(err, pgx.ErrNoRows),
		errmodel.CodeOf(err) == errmodel.CodeInvalidToken:
		return errors.Join(auth.ErrUnauthenticated, auth.ErrRevoked, err)
	default:
		return errors.Join(auth.ErrUnavailable, err)
	}
}
