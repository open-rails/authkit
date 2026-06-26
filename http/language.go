package authhttp

import (
	"net/http"
	"regexp"
	"strings"

	authlang "github.com/open-rails/authkit/lang"
)

// LanguageConfig declares the supported UI languages and default. The query
// parameter and cookie name are NOT configurable — both are hardcoded to
// langSelector ("lang") (#143). No language config means English-only
// (Supported ["en"], default "en").
type LanguageConfig struct {
	Supported []string
	Default   string
}

// langSelector is the fixed query-parameter and cookie name AuthKit reads for
// request language. Not host-configurable (#143).
const langSelector = "lang"

func (c *LanguageConfig) defaulted() LanguageConfig {
	if c == nil {
		return LanguageConfig{Supported: []string{"en"}, Default: "en"}
	}
	out := *c
	if strings.TrimSpace(out.Default) == "" {
		out.Default = "en"
	}
	return out
}

var reSimpleLang = regexp.MustCompile(`^[a-z]{2}$`)

func normalizeLangCode(s string) string {
	s = strings.TrimSpace(strings.ToLower(s))
	if s == "" {
		return ""
	}
	if i := strings.IndexAny(s, "-_"); i >= 0 {
		s = s[:i]
	}
	if !reSimpleLang.MatchString(s) {
		return ""
	}
	return s
}

func supportedSet(supported []string) map[string]struct{} {
	if len(supported) == 0 {
		return nil
	}
	m := make(map[string]struct{}, len(supported))
	for _, s := range supported {
		if n := normalizeLangCode(s); n != "" {
			m[n] = struct{}{}
		}
	}
	return m
}

func pickFromAcceptLanguage(header string, supported map[string]struct{}) string {
	header = strings.TrimSpace(header)
	if header == "" {
		return ""
	}
	parts := strings.Split(header, ",")
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		if i := strings.IndexByte(part, ';'); i >= 0 {
			part = part[:i]
		}
		lang := normalizeLangCode(part)
		if lang == "" {
			continue
		}
		if supported == nil {
			return lang
		}
		if _, ok := supported[lang]; ok {
			return lang
		}
	}
	return ""
}

func pickFromPathPrefix(path string, supported map[string]struct{}) string {
	path = strings.TrimLeft(path, "/")
	if len(path) < 3 {
		return ""
	}
	seg := path
	if i := strings.IndexByte(seg, '/'); i >= 0 {
		seg = seg[:i]
	}
	lang := normalizeLangCode(seg)
	if lang == "" {
		return ""
	}
	if supported == nil {
		return lang
	}
	if _, ok := supported[lang]; ok {
		return lang
	}
	return ""
}

// resolveRequestLanguage implements the shared language contract:
// `?lang` query param > `/:lang/` path prefix > `lang` cookie > `Accept-Language` header > default.
func resolveRequestLanguage(r *http.Request, cfg LanguageConfig) string {
	supported := supportedSet(cfg.Supported)

	if r != nil {
		if qp := normalizeLangCode(r.URL.Query().Get(langSelector)); qp != "" {
			if supported == nil {
				return qp
			}
			if _, ok := supported[qp]; ok {
				return qp
			}
		}

		if lp := pickFromPathPrefix(r.URL.Path, supported); lp != "" {
			return lp
		}

		{
			if c, err := r.Cookie(langSelector); err == nil && c != nil {
				if ck := normalizeLangCode(c.Value); ck != "" {
					if supported == nil {
						return ck
					}
					if _, ok := supported[ck]; ok {
						return ck
					}
				}
			}
		}

		if al := pickFromAcceptLanguage(r.Header.Get("Accept-Language"), supported); al != "" {
			return al
		}
	}

	def := normalizeLangCode(cfg.Default)
	if def != "" {
		if supported == nil {
			return def
		}
		if _, ok := supported[def]; ok {
			return def
		}
	}
	return "en"
}

// LanguageMiddleware infers request language and attaches it to the request context.
func LanguageMiddleware(cfg *LanguageConfig) func(http.Handler) http.Handler {
	c := cfg.defaulted()
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			lang := resolveRequestLanguage(r, c)
			r = r.WithContext(authlang.WithLanguage(r.Context(), lang))
			next.ServeHTTP(w, r)
		})
	}
}
