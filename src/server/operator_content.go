package server

import (
	"html"
	"html/template"
	"log"
	"net/http"
	"regexp"
	"strings"
	"sync"
)

var operatorContentWarnings sync.Map
var operatorHTMLHeading = regexp.MustCompile(`(?i)(</?h)([1-6])(\b[^>]*>)`)

func (s *Server) operatorHTML(r *http.Request, name string) template.HTML {
	var body any
	format := ""
	switch name {
	case "header":
		body, format = s.config.Branding.Content.Header, "html"
	case "about":
		body, format = s.config.Branding.Content.About.Body, s.config.Branding.Content.About.Format
	case "privacy":
		body, format = s.config.Branding.Content.Privacy.Body, s.config.Branding.Content.Privacy.Format
	case "terms":
		body, format = s.config.Branding.Content.Terms.Body, s.config.Branding.Content.Terms.Format
	case "footer":
		body, format = s.config.Branding.Content.Footer.Body, s.config.Branding.Content.Footer.Format
	default:
		return ""
	}
	if name == "footer" && disabledOperatorFooter(body, LangFromContext(r.Context())) {
		return " "
	}
	content, resolvedFormat, valid := resolvedPageContent(body, format, LangFromContext(r.Context()))
	if !valid {
		if invalidOperatorContent(body, format, LangFromContext(r.Context())) {
			warnOperatorContent(name)
		}
		return ""
	}
	content = substitutePageVariables(s, r, content)
	if name == "header" || name == "footer" {
		if resolvedFormat != "html" {
			warnOperatorContent(name)
			return ""
		}
		return template.HTML(SanitizeFooterHTML(content))
	}
	switch resolvedFormat {
	case "markdown":
		return markdownToHTMLSection(content)
	case "html":
		content = operatorHTMLHeading.ReplaceAllStringFunc(content, func(tag string) string {
			parts := operatorHTMLHeading.FindStringSubmatch(tag)
			level := int(parts[2][0]-'0') + 2
			if level > 6 {
				level = 6
			}
			return parts[1] + itoaSmall(level) + parts[3]
		})
		return template.HTML(contentSanitizePolicy.Sanitize(content))
	case "text":
		paragraphs := strings.Split(strings.TrimSpace(content), "\n\n")
		for i, paragraph := range paragraphs {
			paragraphs[i] = "<p>" + strings.ReplaceAll(html.EscapeString(strings.TrimSpace(paragraph)), "\n", "<br>") + "</p>"
		}
		return template.HTML(contentSanitizePolicy.Sanitize(strings.Join(paragraphs, "")))
	default:
		warnOperatorContent(name)
		return ""
	}
}

func invalidOperatorContent(body any, format, language string) bool {
	switch strings.ToLower(format) {
	case "", "md", "markdown", "html", "txt", "text":
	default:
		return hasOperatorContent(body)
	}
	content, ok := contentBody(body, language)
	return ok && len(content) > 256*1024
}

func hasOperatorContent(body any) bool {
	switch value := body.(type) {
	case string:
		return strings.TrimSpace(value) != ""
	case map[string]any:
		for _, entry := range value {
			if text, ok := entry.(string); ok && strings.TrimSpace(text) != "" {
				return true
			}
		}
		return len(value) != 0
	case map[string]string:
		for _, entry := range value {
			if strings.TrimSpace(entry) != "" {
				return true
			}
		}
		return false
	default:
		return body != nil
	}
}

func disabledOperatorFooter(body any, language string) bool {
	var value string
	switch configured := body.(type) {
	case string:
		value = configured
	case map[string]any:
		value, _ = configured[language].(string)
		if value == "" {
			value, _ = configured["default"].(string)
		}
	case map[string]string:
		value = configured[language]
		if value == "" {
			value = configured["default"]
		}
	}
	return value != "" && strings.TrimSpace(value) == ""
}

func warnOperatorContent(name string) {
	if _, loaded := operatorContentWarnings.LoadOrStore(name, true); !loaded {
		log.Printf("WARN: branding.content.%s is invalid; using built-in content", name)
	}
}
