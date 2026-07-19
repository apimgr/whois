package server

import (
	"embed"
	"html/template"
	"io/fs"
	"net/http"

	"github.com/apimgr/whois/src/common/i18n"
)

//go:embed static
var staticFiles embed.FS

//go:embed template
var templateFiles embed.FS

// templateFuncMap holds functions available to all embedded templates.
var templateFuncMap = template.FuncMap{
	"t": translateKey,
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
	raw, err := templateFiles.ReadFile("template/" + file)
	if err != nil {
		panic("failed to read embedded template " + file + ": " + err.Error())
	}
	return template.Must(template.New(name).Funcs(templateFuncMap).Parse(string(raw)))
}

// staticFileServer returns an http.Handler that serves embedded static assets
// under the /static/ URL prefix.
func staticFileServer() http.Handler {
	sub, err := fs.Sub(staticFiles, "static")
	if err != nil {
		panic("failed to sub static embed FS: " + err.Error())
	}
	return http.StripPrefix("/static/", http.FileServer(http.FS(sub)))
}
