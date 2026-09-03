package server

import (
	"context"
	"net/http"

	"github.com/apimgr/whois/src/common/i18n"
)

type contextKey string

const langContextKey contextKey = "lang"

// LanguageMiddleware detects the request language from (in priority order):
// ?lang= query param (also sets a persistent cookie), lang cookie, Accept-Language header, default "en".
func LanguageMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		lang := ""

		// 1. Query parameter — highest priority; also persists choice via cookie
		if q := r.URL.Query().Get("lang"); q != "" && i18n.IsSupported(q) {
			lang = q
			http.SetCookie(w, &http.Cookie{
				Name:     "lang",
				Value:    lang,
				Path:     "/",
				MaxAge:   365 * 24 * 60 * 60,
				SameSite: http.SameSiteLaxMode,
				Secure:   r.TLS != nil,
				HttpOnly: true,
			})
		}

		// 2. Persistent cookie
		if lang == "" {
			if c, err := r.Cookie("lang"); err == nil && i18n.IsSupported(c.Value) {
				lang = c.Value
			}
		}

		// 3. Accept-Language header
		if lang == "" {
			lang = i18n.ParseAcceptLanguage(r.Header.Get("Accept-Language"))
		}

		// 4. Default fallback
		if lang == "" {
			lang = "en"
		}

		ctx := context.WithValue(r.Context(), langContextKey, lang)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// LangFromContext extracts the language code stored by LanguageMiddleware.
// Returns "en" if no language is present in the context.
func LangFromContext(ctx context.Context) string {
	if v, ok := ctx.Value(langContextKey).(string); ok {
		return v
	}
	return "en"
}
