package server

import (
	"fmt"
	"html/template"
	"strings"

	"github.com/microcosm-cc/bluemonday"
)

// FooterData holds the values needed to render the default application
// footer and any operator-supplied custom branding HTML (AI.md PART 16 —
// Footer Customization).
type FooterData struct {
	Lang           string
	TorEnabled     bool
	TorRunning     bool
	OnionAddress   string
	ProjectVersion string
	BuildDatetime  string
	// CustomHTML is the already-sanitized web.footer.custom_html value.
	// "" means "use default branding"; " " means "disable branding row".
	CustomHTML string
	RepoURL    string
}

// footerSanitizePolicy is the strict bluemonday policy for web.footer.custom_html
// (AI.md PART 16 — Footer Customization → Custom HTML Validation). Only basic
// text-formatting tags are allowed; scripts, forms, iframes, and the style
// attribute are always stripped.
var footerSanitizePolicy = newFooterSanitizePolicy()

func newFooterSanitizePolicy() *bluemonday.Policy {
	p := bluemonday.NewPolicy()
	p.AllowElements("p", "br", "span", "div")
	p.AllowElements("strong", "b", "em", "i", "u", "s", "small")
	p.AllowElements("h1", "h2", "h3", "h4", "h5", "h6")
	p.AllowElements("ul", "ol", "li")
	p.AllowAttrs("href", "title", "target", "rel").OnElements("a")
	p.RequireNoReferrerOnLinks(true)
	p.AllowAttrs("src", "alt", "title", "width", "height").OnElements("img")
	p.AllowURLSchemes("https", "data")
	p.AllowAttrs("class", "id").Globally()
	return p
}

// SanitizeFooterHTML sanitizes web.footer.custom_html per AI.md PART 16.
// "" and " " (disable marker) pass through unchanged.
func SanitizeFooterHTML(html string) string {
	if html == "" || html == " " {
		return html
	}
	return footerSanitizePolicy.Sanitize(strings.TrimSpace(html))
}

// renderFooter builds the default application footer HTML (AI.md PART 16 —
// Footer Customization → Default Application Footer). It is registered in
// templateFuncMap as "footer" so every page template can call {{footer .Footer}}.
func renderFooter(fd FooterData) template.HTML {
	var b strings.Builder
	b.WriteString(`<footer class="footer">`)

	if fd.CustomHTML != "" && fd.CustomHTML != " " {
		b.WriteString(`<div class="footer-brand">`)
		b.WriteString(fd.CustomHTML)
		b.WriteString(`</div>`)
	}

	if fd.TorEnabled && fd.TorRunning && fd.OnionAddress != "" {
		fmt.Fprintf(&b, `<p class="footer-onion"><a href="/server/help#tor-access" aria-label="%s">&#129365;</a> <code class="onion-address">%s</code> <button type="button" class="copy-btn" data-copy="%s" aria-live="polite" aria-label="%s">&#128203;</button></p>`,
			template.HTMLEscapeString(translateKey(fd.Lang, "footer.tor_support")),
			template.HTMLEscapeString(fd.OnionAddress),
			template.HTMLEscapeString(fd.OnionAddress),
			template.HTMLEscapeString(translateKey(fd.Lang, "footer.copy_onion")))
	}

	fmt.Fprintf(&b, `<p><a href="/server/about">%s</a><span>&bull;</span><a href="/server/privacy">%s</a><span>&bull;</span><a href="/server/contact">%s</a><span>&bull;</span><a href="/server/help">%s</a></p>`,
		template.HTMLEscapeString(translateKey(fd.Lang, "nav.about")),
		template.HTMLEscapeString(translateKey(fd.Lang, "nav.privacy")),
		template.HTMLEscapeString(translateKey(fd.Lang, "nav.contact")),
		template.HTMLEscapeString(translateKey(fd.Lang, "nav.help")))

	repoURL := fd.RepoURL
	if repoURL == "" {
		repoURL = "https://github.com/apimgr/whois"
	}
	fmt.Fprintf(&b, `<p><a href="%s" target="_blank" rel="noopener noreferrer">%s</a> &#10084;&#65039;<span>&bull;</span><span>%s</span></p>`,
		template.HTMLEscapeString(repoURL),
		template.HTMLEscapeString(translateKey(fd.Lang, "footer.made_with")),
		template.HTMLEscapeString(fd.ProjectVersion))

	fmt.Fprintf(&b, `<p><a href="/server/healthz">%s %s</a></p>`,
		template.HTMLEscapeString(translateKey(fd.Lang, "footer.last_update")),
		template.HTMLEscapeString(fd.BuildDatetime))

	b.WriteString(`</footer>`)
	return template.HTML(b.String())
}
