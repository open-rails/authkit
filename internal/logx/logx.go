// Package logx is where a logger enters AuthKit. Only Or reads slog.Default;
// nothing in AuthKit changes it.
package logx

import "log/slog"

// Or is l, or slog.Default() when l is nil: read once, by the constructor a
// logger enters through.
func Or(l *slog.Logger) *slog.Logger {
	if l == nil {
		return slog.Default()
	}
	return l
}
