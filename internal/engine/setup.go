package engine

// The first administrator. While no usable account holds a role in the root
// group, Start logs a single-use link (Vault's and Jenkins' model): whoever
// opens it creates the owner account with their own password, and the
// owner role makes their first sign-in enroll a second factor. Only the
// link's hash is stored, under one ephemeral key, so at most one link lives.
// Start issues a new one only after it expires; IssueSetupLink is the host's
// break-glass and works while administrators exist.

import (
	"context"
	"encoding/json"
	"errors"
	"net/url"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/internal/config"
	"github.com/open-rails/authkit/internal/db"
	"github.com/open-rails/authkit/internal/errmodel"
	"github.com/open-rails/authkit/internal/secret"
)

const (
	setupLinkKey = "setup:link"
	setupLinkTTL = 24 * time.Hour
)

// setupLink is the stored link: its code's hash, never the code.
type setupLink struct {
	Hash string `json:"hash"`
	// Operator marks IssueSetupLink's link, which administrators do not end.
	Operator  bool      `json:"operator,omitempty"`
	ExpiresAt time.Time `json:"expires_at"`
}

func (s *Engine) setupMounted() bool {
	return config.Mounted(s.cfg, iam.RouteSetup) && s.useEphemeralStore()
}

func (s *Engine) setupURL(code string) string {
	q := url.Values{}
	q.Set("token", code)
	return s.authkitURL(config.SetupPath, q)
}

func newSetupLink(operator bool) (string, []byte, setupLink, error) {
	code := secret.Token(32)
	link := setupLink{Hash: secret.Hash(code), Operator: operator, ExpiresAt: time.Now().UTC().Add(setupLinkTTL).Truncate(time.Second)}
	raw, err := json.Marshal(link)
	return code, raw, link, err
}

// rootStaffed reports whether a usable account holds a role in the root group.
func (s *Engine) rootStaffed(ctx context.Context, q db.DBTX) (bool, error) {
	gid, err := s.rootGroup(ctx, s.groupStoreFor(q))
	if err != nil {
		return false, err
	}
	rows, err := db.New(q).GroupMembersPage(ctx, db.GroupMembersPageParams{
		GroupID: gid, Kinds: []string{string(iam.SubjectKindUser)}, Roles: []string{}, LiveOnly: true, PageLimit: 1,
	})
	return len(rows) > 0, err
}

// announceSetup is Start's part: with no administrator, it logs a new setup
// link, or when one still lives, when it expires. It never fails Start.
func (s *Engine) announceSetup(ctx context.Context) {
	if !s.setupMounted() {
		return
	}
	staffed, err := s.rootStaffed(ctx, s.pg)
	if err != nil {
		s.log.ErrorContext(ctx, "authkit: setup: cannot tell whether an administrator exists", "error", err)
		return
	}
	if staffed {
		return
	}
	code, raw, link, err := newSetupLink(false)
	if err != nil {
		s.log.ErrorContext(ctx, "authkit: setup: cannot issue a setup link", "error", err)
		return
	}
	issued, err := s.ephemeral.Swap(ctx, setupLinkKey, nil, raw, setupLinkTTL)
	if err != nil {
		s.log.ErrorContext(ctx, "authkit: setup: cannot issue a setup link", "error", err)
		return
	}
	if issued {
		s.log.WarnContext(ctx, "authkit: no administrator yet: open this single-use link to create the owner account", "url", s.setupURL(code), "expires_at", link.ExpiresAt)
		return
	}
	var live setupLink
	if ok, err := s.ephemGetJSON(ctx, setupLinkKey, &live); err == nil && ok {
		s.log.WarnContext(ctx, "authkit: no administrator yet: the setup link logged earlier works until it expires; the host's IssueSetupLink issues a new one", "expires_at", live.ExpiresAt)
	}
}

// IssueSetupLink issues a new setup link, replacing any live one. Its owner
// account is created whether or not administrators exist: a host's
// break-glass, run from its own shell.
func (s *Engine) IssueSetupLink(ctx context.Context) (iam.SetupLink, error) {
	if err := s.requirePG(); err != nil {
		return iam.SetupLink{}, err
	}
	if !s.setupMounted() {
		return iam.SetupLink{}, errors.New("authkit: IssueSetupLink needs HTTP.Groups to mount iam.RouteSetup")
	}
	code, raw, link, err := newSetupLink(true)
	if err != nil {
		return iam.SetupLink{}, err
	}
	if err := s.ephemeral.Set(ctx, setupLinkKey, raw, setupLinkTTL); err != nil {
		return iam.SetupLink{}, err
	}
	return iam.SetupLink{URL: s.setupURL(code), ExpiresAt: link.ExpiresAt}, nil
}

// CompleteSetup spends a setup link on the owner account: n's email,
// username and password, holding root's owner role. The account's email
// stays unproven, as for any host-created account. A link Start issued is
// refused once a usable account holds a root role.
func (s *Engine) CompleteSetup(ctx context.Context, code string, n iam.NewUser) (iam.User, error) {
	if err := s.requirePG(); err != nil {
		return iam.User{}, err
	}
	if !s.setupMounted() {
		return iam.User{}, iam.ErrSetupLinkInvalid
	}
	// The link is checked before the password is hashed, so a guess costs
	// one read.
	var link setupLink
	raw, ok, err := s.ephemReadJSON(ctx, setupLinkKey, &link)
	if err != nil {
		return iam.User{}, err
	}
	code = strings.TrimSpace(code)
	if !ok || code == "" || !secret.Equal(secret.Hash(code), link.Hash) {
		return iam.User{}, iam.ErrSetupLinkInvalid
	}
	if strings.TrimSpace(n.Email) == "" || strings.TrimSpace(n.Username) == "" || n.Password == "" {
		return iam.User{}, errmodel.E(errmodel.CodeMissingFields)
	}
	if err := s.ValidateUsername(n.Username); err != nil {
		return iam.User{}, err
	}
	acct, err := s.prepareUser(ctx, iam.NewUser{Email: n.Email, Username: n.Username, Password: n.Password})
	if err != nil {
		return iam.User{}, err
	}
	var out iam.User
	err = s.withAuthorityMutationIn(ctx, iam.SystemIdentity(), nil, func(st *permissionGroupStore) error {
		if !link.Operator {
			staffed, err := s.rootStaffed(ctx, st.q)
			if err != nil {
				return err
			}
			if staffed {
				return iam.ErrSetupLinkInvalid
			}
		}
		spent, err := db.New(st.q).EphemeralCompareAndConsume(ctx, db.EphemeralCompareAndConsumeParams{Key: setupLinkKey, Expected: raw})
		if err != nil {
			return err
		}
		if spent != 1 {
			return iam.ErrSetupLinkInvalid
		}
		tx, ok := st.q.(pgx.Tx)
		if !ok {
			return errors.New("authkit: setup runs in its own authority transaction")
		}
		owner, err := s.insertUser(ctx, tx, acct)
		if err != nil {
			return err
		}
		root, err := s.rootGroup(ctx, st)
		if err != nil {
			return err
		}
		if err := st.AssignRole(ctx, root, iam.UserSubject(owner.ID), iam.RootPersona().OwnerRole()); err != nil {
			return err
		}
		out = owner
		return nil
	})
	if err != nil {
		return iam.User{}, err
	}
	return out, nil
}
