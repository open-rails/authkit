package core

import "strings"

var reservedUsernames = map[string]struct{}{
	"admin":     {},
	"moderator": {},
	"root":      {},
	"sudo":      {},
	"superuser": {},
}

func IsReservedUsername(username string) bool {
	_, ok := reservedUsernames[strings.ToLower(strings.TrimSpace(username))]
	return ok
}
