package jwtkit

// Logger receives non-fatal key-loading warnings from jwtkit. The default is a
// no-op logger so libraries do not write to stdout.
type Logger func(format string, args ...any)

var packageLogger Logger = func(string, ...any) {}

// SetLogger installs the package-level logger used for key-load warnings.
// Pass nil to restore the default no-op logger.
func SetLogger(l Logger) {
	if l == nil {
		packageLogger = func(string, ...any) {}
		return
	}
	packageLogger = l
}

func logf(format string, args ...any) {
	if packageLogger != nil {
		packageLogger(format, args...)
	}
}
