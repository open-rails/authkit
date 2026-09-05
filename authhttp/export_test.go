package authhttp

import "sync"

// resetOIDCManagerForTest clears the lazy OIDC manager so a test can mutate
// providers after New.
func (s *Service) resetOIDCManagerForTest() {
	s.oidcMgrOnce = sync.Once{}
	s.oidcMgr = nil
}
