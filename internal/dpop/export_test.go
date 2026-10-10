package dpop

import "time"

// IssueAt and ValidAt are Issue and Valid at a given time, for tests.
func (n *Nonces) IssueAt(now time.Time) string             { return n.issue(now) }
func (n *Nonces) ValidAt(nonce string, now time.Time) bool { return n.valid(nonce, now) }
