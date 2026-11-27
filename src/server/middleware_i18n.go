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
	return languageMiddleware(next, nil)
}

func (s *Server) languageMiddleware(next http.Handler) http.Handler {
	return languageMiddleware(next, s)
}

func languageMiddleware(next http.Handler, server *Server) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		lang := ""

		// 1. Query parameter — highest priority; persistence requires consent.
		if q := r.URL.Query().Get("lang"); q != "" {
			queryLanguage := ""
			if server != nil {
				queryLanguage = server.canonicalPreferenceLanguage(q)
			} else if i18n.IsSupported(q) {
				queryLanguage = q
			}
			if queryLanguage == "" {
				lang = "en"
			} else {
				lang = queryLanguage
				consent := getConsentFromRequest(r)
				if consent != nil && consent.Preferences {
					if server != nil {
						server.setPreferenceCookie(w, r, "lang", lang)
					} else {
						http.SetCookie(w, &http.Cookie{Name: "lang", Value: lang, Path: "/", MaxAge: preferencesCookieAge,
							SameSite: http.SameSiteLaxMode, Secure: r.TLS != nil, HttpOnly: false})
					}
				}
			}
		}

		// 2. Persistent cookie
		if lang == "" {
			if c, err := r.Cookie("lang"); err == nil {
				if server != nil {
					lang = server.canonicalPreferenceLanguage(c.Value)
				} else if i18n.IsSupported(c.Value) {
					lang = c.Value
				}
			}
		}

		// 3. Accept-Language header
		if lang == "" {
			if server != nil {
				lang = i18n.ParseAcceptLanguageFor(r.Header.Get("Accept-Language"), server.config.I18n.Supported)
			} else {
				lang = i18n.ParseAcceptLanguage(r.Header.Get("Accept-Language"))
			}
		}

		// 4. Default fallback
		if lang == "" {
			lang = "en"
		}
		if server != nil && server.canonicalPreferenceLanguage(lang) == "" {
			lang = "en"
		}
		w.Header().Set("Content-Language", lang)
		addVaryHeader(w.Header(), "Accept-Language")

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
