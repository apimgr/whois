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
	"t":                     translateKey,
	"tf":                    translateFormat,
	"tp":                    translatePlural,
	"footer":                renderFooter,
	"markdownToHTML":        markdownToHTML,
	"markdownToHTMLSection": markdownToHTMLSection,
	"humanize":              humanize,
	"path":                  func(value string) string { return value },
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
func staticFileServer() http.Handler {
	sub, err := fs.Sub(staticFiles, "static")
	if err != nil {
		panic("failed to sub static embed FS: " + err.Error())
	}
	return http.StripPrefix("/static/", http.FileServer(http.FS(sub)))
}
