package server

import (
	"fmt"
	"io"
	"io/fs"
	"os"
	"regexp"
	"strings"
	"testing"

	"github.com/tdewolff/parse/v2"
	cssparser "github.com/tdewolff/parse/v2/css"
)

var (
	cssClassSelector = regexp.MustCompile(`\.[_a-zA-Z][-_a-zA-Z0-9]*`)
	cssIDSelector    = regexp.MustCompile(`#[_a-zA-Z][-_a-zA-Z0-9]*`)
	cssPseudo        = regexp.MustCompile(`:{1,2}[-_a-zA-Z][-_a-zA-Z0-9]*(?:\([^)]*\))?`)
	cssPseudoElement = regexp.MustCompile(`::[-_a-zA-Z][-_a-zA-Z0-9]*`)
	cssTypeSelector  = regexp.MustCompile(`(?:^|[\s>+~])([a-zA-Z][-_a-zA-Z0-9]*)`)
	cssAttribute     = regexp.MustCompile(`\[[^]]+\]`)
	cssDimension     = regexp.MustCompile(`(?i)(?:^|[^a-z0-9_-])([1-9][0-9]*(?:\.[0-9]+)?|0\.[0-9]+)(px|rem|em|vh|vw|dvh|dvw|ch|ex|%)\b`)
	cssColorLiteral  = regexp.MustCompile(`(?i)#[0-9a-f]{3,8}\b|\b(?:rgb|rgba|hsl|hsla)\s*\(|\b(?:black|white|red|green|blue|yellow|purple|orange|gray|grey|silver|maroon|navy|teal|lime|aqua|fuchsia)\b`)
	cssPhysicalProp  = regexp.MustCompile(`(?i)^(?:margin|padding|border)-(?:left|right|top|bottom)(?:-|$)|^(?:left|right|top|bottom)$`)
)

type cssScope struct {
	layer string
	media string
}

func TestEmbeddedCSSContract(t *testing.T) {
	documented := documentedCSSClasses(t)
	files, err := fs.Glob(staticFiles, "static/css/*.css")
	if err != nil {
		t.Fatal(err)
	}
	if len(files) == 0 {
		t.Fatal("no embedded CSS files found")
	}
	for _, file := range files {
		file := file
		t.Run(file, func(t *testing.T) {
			data, err := staticFiles.ReadFile(file)
			if err != nil {
				t.Fatal(err)
			}
			if err := checkCSSContract(data, documented); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func checkCSSContract(source []byte, documented map[string]bool) error {
	parser := cssparser.NewParser(parse.NewInput(strings.NewReader(string(source))), false)
	var scopes []cssScope
	for {
		grammar, _, token := parser.Next()
		if parser.Err() == io.EOF {
			break
		}
		if grammar == cssparser.ErrorGrammar {
			return fmt.Errorf("CSS parse error at byte %d: %w", parser.Offset(), parser.Err())
		}
		switch grammar {
		case cssparser.BeginAtRuleGrammar:
			prelude := strings.ToLower(cssTokens(parser.Values()))
			next := cssScope{}
			switch strings.ToLower(string(token)) {
			case "@layer":
				next.layer = prelude
			case "@media":
				next.media = prelude
			}
			scopes = append(scopes, next)
		case cssparser.EndAtRuleGrammar:
			if len(scopes) > 0 {
				scopes = scopes[:len(scopes)-1]
			}
		case cssparser.BeginRulesetGrammar:
			selector := cssTokens(parser.Values())
			layer := currentCSSScope(scopes, true)
			if layer == "" {
				return fmt.Errorf("unlayered selector %q", selector)
			}
			if matches := cssIDSelector.FindAllString(selector, -1); len(matches) > 0 {
				return fmt.Errorf("ID selector %q in %q", matches[0], selector)
			}
			for _, class := range cssClassSelector.FindAllString(selector, -1) {
				name := strings.TrimPrefix(class, ".")
				if !documented[name] {
					return fmt.Errorf("uncatalogued class selector %q in %q", class, selector)
				}
			}
			if layer == "components" {
				if err := checkCSSSpecificity(selector); err != nil {
					return err
				}
				if err := checkCSSDescendantSubjects(selector); err != nil {
					return err
				}
			}
		case cssparser.DeclarationGrammar, cssparser.CustomPropertyGrammar:
			declaration := strings.ToLower(cssTokens(parser.Values()))
			property, value, found := strings.Cut(declaration, ":")
			property = strings.TrimSpace(property)
			value = strings.TrimSpace(value)
			if found {
				if cssPhysicalProp.MatchString(property) {
					return fmt.Errorf("physical CSS property %q; use logical properties", property)
				}
				if currentCSSScope(scopes, true) != "tokens" {
					if (property == "font-size" || strings.HasPrefix(property, "margin") || strings.HasPrefix(property, "padding") || property == "gap" || property == "row-gap" || property == "column-gap" || property == "border-radius") && hasLiteralDimension(value) {
						return fmt.Errorf("literal size in %q: %s", property, value)
					}
					colorProperty := property == "color" || strings.Contains(property, "color") || property == "background" || strings.HasPrefix(property, "border") || property == "outline"
					if colorProperty && cssColorLiteral.MatchString(value) && !onlyCSSColorKeywords(value) {
						return fmt.Errorf("literal color in %q: %s", property, value)
					}
				}
			}
			if strings.Contains(declaration, "! important") || strings.Contains(declaration, "!important") {
				media := currentCSSScope(scopes, false)
				if currentCSSScope(scopes, true) != "utilities" || !(strings.Contains(media, "print") || strings.Contains(media, "prefers-reduced-motion")) {
					return fmt.Errorf("!important outside the print or reduced-motion utility blocks: %s", declaration)
				}
			}
		}
		if grammar == cssparser.ErrorGrammar {
			return parser.Err()
		}
	}
	return nil
}

func hasLiteralDimension(value string) bool {
	return len(cssDimension.FindAllStringSubmatch(value, -1)) > 0
}

func onlyCSSColorKeywords(value string) bool {
	value = strings.ToLower(strings.TrimSpace(value))
	return value == "transparent" || value == "currentcolor" || value == "inherit" || value == "initial" || value == "unset"
}

func checkCSSDescendantSubjects(selector string) error {
	owned := map[string]map[string]bool{
		"toggle":           {"input": true},
		"check":            {"input": true},
		"data-table":       {"th": true, "td": true},
		"info-list":        {"dt": true, "dd": true},
		"code-block":       {"code": true},
		"code-block-multi": {"pre": true, "code": true},
		"site-footer":      {"a": true},
	}
	combinator := regexp.MustCompile(`\s*[>+~]\s*|\s+`)
	element := regexp.MustCompile(`^([a-z][a-z0-9-]*)(.*)$`)
	for _, part := range strings.Split(selector, ",") {
		compounds := combinator.Split(strings.TrimSpace(part), -1)
		if len(compounds) < 2 {
			continue
		}
		match := element.FindStringSubmatch(compounds[len(compounds)-1])
		if len(match) == 0 || (match[2] != "" && !strings.HasPrefix(match[2], ":") && !strings.HasPrefix(match[2], "[")) {
			continue
		}
		parentClasses := cssClassSelector.FindAllString(compounds[len(compounds)-2], -1)
		allowed := false
		for _, class := range parentClasses {
			if owned[strings.TrimPrefix(class, ".")][match[1]] {
				allowed = true
				break
			}
		}
		if !allowed {
			return fmt.Errorf("bare element subject %q under generic or foreign component in %q", match[1], strings.TrimSpace(part))
		}
	}
	return nil
}

func documentedCSSClasses(t *testing.T) map[string]bool {
	t.Helper()
	spec, err := os.ReadFile("../../AI.md")
	if err != nil {
		t.Fatalf("read CSS class catalog from AI.md: %v", err)
	}
	classPattern := regexp.MustCompile(`\.([A-Za-z_][A-Za-z0-9_-]*)`)
	documented := make(map[string]bool)
	for _, match := range classPattern.FindAllSubmatch(spec, -1) {
		documented[string(match[1])] = true
	}
	for _, match := range regexp.MustCompile(`--icon-(sm|md|lg|xl)`).FindAllStringSubmatch(string(spec), -1) {
		documented["icon-"+string(match[1])] = true
	}
	for _, match := range regexp.MustCompile("(?m)\\bclass=[\\\"']([^\\\"']+)['\\\"]").FindAllSubmatch(spec, -1) {
		for _, name := range strings.Fields(string(match[1])) {
			documented[name] = true
		}
	}
	for _, match := range regexp.MustCompile(`\.([A-Za-z_][A-Za-z0-9_-]*)-\{([^}]+)\}`).FindAllSubmatch(spec, -1) {
		base := string(match[1])
		for _, suffix := range strings.Split(string(match[2]), ",") {
			documented[base+"-"+strings.TrimSpace(suffix)] = true
		}
	}
	for _, line := range strings.Split(string(spec), "\n") {
		if !strings.HasPrefix(line, "|") || !strings.Contains(line, "`.") {
			continue
		}
		columns := strings.Split(line, "|")
		if len(columns) < 5 {
			continue
		}
		blocks := classPattern.FindAllStringSubmatch(columns[2], -1)
		variants := regexp.MustCompile("`(-[A-Za-z0-9_-]+)`").FindAllStringSubmatch(columns[3], -1)
		sizes := regexp.MustCompile("`?(sm|md|lg|xl)`?").FindAllStringSubmatch(columns[4], -1)
		for _, block := range blocks {
			for _, variant := range variants {
				documented[string(block[1])+variant[1]] = true
			}
			for _, size := range sizes {
				documented[string(block[1])+"-"+size[1]] = true
			}
		}
	}
	return documented
}

func cssTokens(tokens []cssparser.Token) string {
	var value strings.Builder
	for _, token := range tokens {
		value.Write(token.Data)
	}
	return value.String()
}

func currentCSSScope(scopes []cssScope, layer bool) string {
	for index := len(scopes) - 1; index >= 0; index-- {
		if layer && scopes[index].layer != "" {
			return scopes[index].layer
		}
		if !layer && scopes[index].media != "" {
			return scopes[index].media
		}
	}
	return ""
}

func checkCSSSpecificity(selector string) error {
	for _, part := range strings.Split(selector, ",") {
		pseudoClasses := len(cssPseudo.FindAllString(part, -1)) - len(cssPseudoElement.FindAllString(part, -1))
		classes := len(cssClassSelector.FindAllString(part, -1)) + pseudoClasses
		elements := len(cssTypeSelector.FindAllString(part, -1)) + len(cssPseudoElement.FindAllString(part, -1))
		for range cssAttribute.FindAllString(part, -1) {
			classes++
		}
		if classes > 4 || elements > 1 {
			return fmt.Errorf("component selector exceeds specificity (0,4,1): %q", strings.TrimSpace(part))
		}
	}
	return nil
}
