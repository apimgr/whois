package server

import (
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"html/template"
	"io/fs"
	"net/http"
	"net/url"
	"strings"

	"github.com/apimgr/whois/src/common/i18n"
)

//go:embed static
var staticFiles embed.FS

//go:embed template
var templateFiles embed.FS

// templateFuncMap holds functions available to all embedded templates.
var templateFuncMap = template.FuncMap{
	"t":                     translateKey,
	"tf":                    translateFormat,
	"tp":                    translatePlural,
	"footer":                renderFooter,
	"markdownToHTML":        markdownToHTML,
	"markdownToHTMLSection": markdownToHTMLSection,
	"humanize":              humanize,
	"operatorHTML":          func(string) template.HTML { return "" },
	"path":                  func(value string) string { return value },
	"asset":                 assetURL,
}

func assetURL(path string) string {
	path = strings.TrimLeft(path, "/")
	return "/static/" + path + "?v=" + url.QueryEscape(Version+"-"+CommitID)
}

// translateFormat applies literal named replacements to a translated message.
func translateFormat(lang, key string, pairs ...string) string {
	args := make(map[string]string, len(pairs)/2)
	for index := 0; index+1 < len(pairs); index += 2 {
		args[pairs[index]] = pairs[index+1]
	}
	return i18n.TranslateFormat(lang, key, args)
}

// translatePlural renders a CLDR plural message for a template value.
func translatePlural(lang, key string, count int) string {
	return i18n.TranslatePlural(lang, key, count)
}

// translateKey looks up a translation key for the given language, falling
// back to English when the language is unsupported or fails to load.
func translateKey(lang, key string) string {
	tr, err := i18n.Load(lang)
	if err != nil {
		tr, err = i18n.Load("en")
		if err != nil {
			return key
		}
	}
	return tr.T(key)
}

// mustParseTemplate loads and parses a named template from the embedded FS.
// Panics on error (same behaviour as template.Must).
func mustParseTemplate(name, file string) *template.Template {
	parsed := template.New(name).Funcs(templateFuncMap)
	for _, shared := range []string{
		"template/layout/public.tmpl",
		"template/partial/head.tmpl",
		"template/partial/scripts.tmpl",
		"template/partial/public/header.tmpl",
		"template/partial/public/nav.tmpl",
		"template/partial/public/footer.tmpl",
		"template/partial/public/theme_toggle.tmpl",
	} {
		raw, err := templateFiles.ReadFile(shared)
		if err != nil {
			panic("failed to read shared embedded template " + shared + ": " + err.Error())
		}
		parsed = template.Must(parsed.Parse(string(raw)))
	}
	page, err := templateFiles.ReadFile("template/" + file)
	if err != nil {
		panic("failed to read embedded template " + file + ": " + err.Error())
	}
	return template.Must(parsed.Parse(string(page)))
}

// mustParsePartial loads a reusable fragment outside the public page layout.
func mustParsePartial(name, file string) *template.Template {
	raw, err := templateFiles.ReadFile("template/" + file)
	if err != nil {
		panic("failed to read embedded partial " + file + ": " + err.Error())
	}
	return template.Must(template.New(name).Funcs(templateFuncMap).Parse(string(raw)))
}

// staticFileServer returns an http.Handler that serves embedded static assets
// under the /static/ URL prefix.
func staticFileServer(servers ...*Server) http.Handler {
	sub, err := fs.Sub(staticFiles, "static")
	if err != nil {
		panic("failed to sub static embed FS: " + err.Error())
	}
	files := http.StripPrefix("/static/", http.FileServer(http.FS(sub)))
	stamp := Version + "-" + CommitID
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if len(servers) > 0 && servers[0] != nil {
			var asset string
			switch {
			case strings.HasSuffix(strings.Trim(r.URL.Path, "/"), "static/css/common.css"):
				asset = "css/common.css"
			case strings.HasSuffix(strings.Trim(r.URL.Path, "/"), "static/css/components.css"):
				asset = "css/components.css"
			}
			if asset != "" {
				content, err := fs.ReadFile(sub, asset)
				if err != nil {
					http.NotFound(w, r)
					return
				}
				if asset == "css/common.css" {
					content = append(content, []byte("\n"+accentTokenCSS(servers[0].config.Web.UI.Accent))...)
				} else {
					content = append(content, []byte("\n"+notificationsCSSContent(servers[0]))...)
				}
				serveDynamicCSS(w, r, content)
				return
			}
		}
		etag := `"` + stamp + `"`
		w.Header().Set("ETag", etag)
		if r.URL.Query().Get("v") == stamp {
			w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
		} else {
			w.Header().Set("Cache-Control", "no-cache")
		}
		if r.Header.Get("If-None-Match") == etag {
			w.WriteHeader(http.StatusNotModified)
			return
		}
		files.ServeHTTP(w, r)
	})
}

func serveDynamicCSS(w http.ResponseWriter, r *http.Request, content []byte) {
	digest := sha256.Sum256(content)
	etag := `"` + hex.EncodeToString(digest[:]) + `"`
	w.Header().Set("Content-Type", "text/css; charset=utf-8")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("ETag", etag)
	if r.Header.Get("If-None-Match") == etag {
		w.WriteHeader(http.StatusNotModified)
		return
	}
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(content)
}
