package server

import (
	"html"
	"html/template"
	"regexp"
	"strings"

	"github.com/microcosm-cc/bluemonday"
)

// contentSanitizePolicy is the bluemonday policy applied to rendered Markdown
// content on the /server/privacy, /server/help, and /server/terms pages
// (AI.md PART 16 — Standard Pages, Markdown content overrides). It allows
// only the prose elements produced by markdownToHTML; raw HTML from the
// source is never passed through unsanitized (AI.md PART 16 — Go Templates,
// markdownToHTML requirements).
var contentSanitizePolicy = newContentSanitizePolicy()

func newContentSanitizePolicy() *bluemonday.Policy {
	p := bluemonday.NewPolicy()
	p.AllowElements("p", "br", "strong", "em", "u", "s", "small", "code", "pre", "blockquote")
	p.AllowElements("h1", "h2", "h3", "h4", "h5", "h6")
	p.AllowElements("ul", "ol", "li")
	p.AllowAttrs("href", "title", "target", "rel").OnElements("a")
	p.AllowURLSchemes("https", "http", "mailto")
	p.AllowAttrs("class", "id").Globally()
	return p
}

// mdHeadingPattern matches ATX-style Markdown headings (# .. ######).
var mdHeadingPattern = regexp.MustCompile(`(?m)^(#{1,6})\s+(.+)$`)

// mdBoldPattern matches **bold** text.
var mdBoldPattern = regexp.MustCompile(`\*\*(.+?)\*\*`)

// mdItalicPattern matches *italic* text.
var mdItalicPattern = regexp.MustCompile(`\*(.+?)\*`)

// mdLinkPattern matches [text](url) links.
var mdLinkPattern = regexp.MustCompile(`\[([^\]]+)\]\(([^)]+)\)`)

// mdListItemPattern matches a single "- item" or "* item" bullet line.
var mdListItemPattern = regexp.MustCompile(`(?m)^[-*]\s+(.+)$`)

// markdownToHTML renders a small, safe subset of Markdown (headings, bold,
// italic, links, bullet lists, paragraphs) to sanitized HTML for use in
// operator-supplied content overrides (AI.md PART 16 — Standard Pages, Go
// Templates → markdownToHTML requirements). The source text is HTML-escaped
// before any markup is generated, so raw HTML in the source never passes
// through; external links get safe rel attributes; the final HTML is run
// through an allow-list sanitizer before being returned as template.HTML.
// Registered in templateFuncMap as "markdownToHTML".
func markdownToHTML(src string) template.HTML {
	src = strings.TrimSpace(src)
	if src == "" {
		return ""
	}

	// Escape any raw HTML in the source first — markdown syntax below only
	// ever introduces the specific tags this function controls.
	src = html.EscapeString(src)

	// Headings first (line-based, must run before paragraph wrapping).
	src = mdHeadingPattern.ReplaceAllStringFunc(src, func(m string) string {
		parts := mdHeadingPattern.FindStringSubmatch(m)
		level := itoaSmall(len(parts[1]))
		return "<h" + level + ">" + parts[2] + "</h" + level + ">"
	})

	// Bullet lists: group consecutive "- item" lines into a <ul>.
	src = renderMarkdownLists(src)

	// Inline formatting. Links get the safe external-link rel attributes
	// (AI.md PART 16 — markdownToHTML requirements).
	src = mdLinkPattern.ReplaceAllString(src, `<a href="$2" rel="noopener noreferrer nofollow ugc">$1</a>`)
	src = mdBoldPattern.ReplaceAllString(src, "<strong>$1</strong>")
	src = mdItalicPattern.ReplaceAllString(src, "<em>$1</em>")

	// Remaining blank-line-separated blocks become paragraphs, skipping
	// blocks that are already block-level elements.
	blocks := strings.Split(src, "\n\n")
	var out strings.Builder
	for _, block := range blocks {
		block = strings.TrimSpace(block)
		if block == "" {
			continue
		}
		if strings.HasPrefix(block, "<h") || strings.HasPrefix(block, "<ul") || strings.HasPrefix(block, "<ol") {
			out.WriteString(block)
			continue
		}
		out.WriteString("<p>")
		out.WriteString(strings.ReplaceAll(block, "\n", " "))
		out.WriteString("</p>")
	}

	return template.HTML(contentSanitizePolicy.Sanitize(out.String()))
}

// renderMarkdownLists groups consecutive "- item"/"* item" lines into <ul><li>…</li></ul>.
func renderMarkdownLists(src string) string {
	lines := strings.Split(src, "\n")
	var out []string
	var listItems []string
	flush := func() {
		if len(listItems) == 0 {
			return
		}
		out = append(out, "<ul><li>"+strings.Join(listItems, "</li><li>")+"</li></ul>")
		listItems = nil
	}
	for _, line := range lines {
		if m := mdListItemPattern.FindStringSubmatch(line); m != nil {
			listItems = append(listItems, m[1])
			continue
		}
		flush()
		out = append(out, line)
	}
	flush()
	return strings.Join(out, "\n")
}

// itoaSmall converts a small non-negative int (0-9) to its decimal string.
func itoaSmall(n int) string {
	if n < 0 || n > 9 {
		return "6"
	}
	return string(rune('0' + n))
}

// humanize converts a snake_case machine token (e.g. "user_initiated") into a
// readable phrase ("User initiated") for display on the /server/privacy page
// (AI.md PART 16 — Standard Pages, Data Storage section: `.Condition | humanize`).
// Registered in templateFuncMap as "humanize".
func humanize(s string) string {
	s = strings.ReplaceAll(s, "_", " ")
	s = strings.ReplaceAll(s, "-", " ")
	s = strings.TrimSpace(s)
	if s == "" {
		return s
	}
	return strings.ToUpper(s[:1]) + s[1:]
}
