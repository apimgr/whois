// Command i18n-validate checks embedded locale files against the shared
// internationalization registry and the English message catalog.
package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/apimgr/whois/src/common/i18n"
)

var interpVarPattern = regexp.MustCompile(`\{[a-zA-Z0-9_]+\}`)
var positionalVerbPattern = regexp.MustCompile(`%[-+0-9.#]*[sd]`)

type localeMessages struct {
	strings map[string]string
	plurals map[string]map[string]string
	meta    map[string]string
}

func main() {
	dir := "src/common/i18n/locales"
	if len(os.Args) > 1 {
		dir = os.Args[1]
	}
	if err := validate(dir); err != nil {
		fmt.Fprintf(os.Stderr, "i18n-validate: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("i18n-validate: OK — locale files match the registry, keys, placeholders, and plural rules")
}

func validate(dir string) error {
	registered := make(map[string]i18n.Locale, len(i18n.Registry))
	for _, locale := range i18n.Registry {
		registered[locale.Code] = locale
	}
	if !sameSet(i18n.SupportedLanguages(), mapKeys(registered)) {
		return fmt.Errorf("runtime language list does not match the registry")
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return fmt.Errorf("reading locale directory: %w", err)
	}
	files := make(map[string]bool)
	for _, entry := range entries {
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".json" {
			continue
		}
		files[strings.TrimSuffix(entry.Name(), ".json")] = true
	}
	if !sameSet(mapKeys(files), mapKeys(registered)) {
		return fmt.Errorf("locale files %v do not match registered languages %v", mapKeys(files), mapKeys(registered))
	}
	all := make(map[string]localeMessages, len(registered))
	for code, spec := range registered {
		messages, err := loadMessages(filepath.Join(dir, code+".json"))
		if err != nil {
			return fmt.Errorf("%s: %w", code, err)
		}
		if err := validateMetadata(code, spec, messages.meta); err != nil {
			return err
		}
		all[code] = messages
	}

	english := all["en"]
	englishKeys := messageKeys(english)
	for code, locale := range all {
		if code == "en" {
			continue
		}
		if missing := diffKeys(englishKeys, messageKeys(locale)); len(missing) > 0 {
			return fmt.Errorf("%s is missing message key(s): %s", code, strings.Join(missing, ", "))
		}
		if extra := diffKeys(messageKeys(locale), englishKeys); len(extra) > 0 {
			return fmt.Errorf("%s has orphaned message key(s): %s", code, strings.Join(extra, ", "))
		}
	}
	for code, locale := range all {
		if err := validateStrings(code, locale.strings); err != nil {
			return err
		}
		for key, englishValue := range english.strings {
			localeValue, ok := locale.strings[key]
			if !ok {
				continue
			}
			if !sameSet(interpVarPattern.FindAllString(englishValue, -1), interpVarPattern.FindAllString(localeValue, -1)) {
				return fmt.Errorf("%s key %q interpolation variables do not match English", code, key)
			}
		}
		if err := validatePluralMessages(code, registered[code], english.plurals, locale.plurals); err != nil {
			return err
		}
	}
	return nil
}

func loadMessages(path string) (localeMessages, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return localeMessages{}, fmt.Errorf("reading file: %w", err)
	}
	var tree map[string]interface{}
	if err := json.Unmarshal(raw, &tree); err != nil {
		return localeMessages{}, fmt.Errorf("parsing JSON: %w", err)
	}
	result := localeMessages{strings: map[string]string{}, plurals: map[string]map[string]string{}, meta: map[string]string{}}
	if err := flattenMessages("", tree, &result); err != nil {
		return localeMessages{}, err
	}
	for key, value := range result.strings {
		if strings.HasPrefix(key, "meta.") {
			result.meta[strings.TrimPrefix(key, "meta.")] = value
		}
	}
	return result, nil
}

func flattenMessages(prefix string, node map[string]interface{}, out *localeMessages) error {
	if strings.HasPrefix(prefix, "plurals.") && isPluralCategoryMap(node) {
		categories := make(map[string]string, len(node))
		for category, value := range node {
			text, ok := value.(string)
			if !ok {
				return fmt.Errorf("plural %q category %q must be a string", prefix, category)
			}
			categories[category] = text
		}
		out.plurals[prefix] = categories
		return nil
	}
	for key, value := range node {
		path := key
		if prefix != "" {
			path = prefix + "." + key
		}
		switch item := value.(type) {
		case map[string]interface{}:
			if err := flattenMessages(path, item, out); err != nil {
				return err
			}
		case string:
			out.strings[path] = item
		default:
			return fmt.Errorf("%s must be a string or object", path)
		}
	}
	return nil
}

func isPluralCategoryMap(node map[string]interface{}) bool {
	if len(node) == 0 {
		return false
	}
	for key := range node {
		switch key {
		case "zero", "one", "two", "few", "many", "other":
		default:
			return false
		}
	}
	return true
}

func validateMetadata(code string, spec i18n.Locale, metadata map[string]string) error {
	if metadata["language"] != code {
		return fmt.Errorf("%s metadata language is %q", code, metadata["language"])
	}
	if metadata["name"] != spec.Name {
		return fmt.Errorf("%s metadata name is %q, want %q", code, metadata["name"], spec.Name)
	}
	if metadata["native_name"] != spec.NativeName {
		return fmt.Errorf("%s native name is %q, want %q", code, metadata["native_name"], spec.NativeName)
	}
	if metadata["direction"] != spec.Direction {
		return fmt.Errorf("%s direction is %q, want %q", code, metadata["direction"], spec.Direction)
	}
	return nil
}

func messageKeys(messages localeMessages) map[string]string {
	keys := make(map[string]string, len(messages.strings)+len(messages.plurals))
	for key, value := range messages.strings {
		keys[key] = value
	}
	for key := range messages.plurals {
		keys[key] = ""
	}
	return keys
}

func validateStrings(code string, values map[string]string) error {
	for key, value := range values {
		if strings.TrimSpace(value) == "" {
			return fmt.Errorf("%s key %q has an empty value", code, key)
		}
		if positionalVerbPattern.MatchString(value) {
			return fmt.Errorf("%s key %q contains a positional format verb; use named placeholders", code, key)
		}
	}
	return nil
}

func validatePluralMessages(code string, spec i18n.Locale, english, locale map[string]map[string]string) error {
	for key, categories := range locale {
		actual := mapKeys(categories)
		validCategories := sameSet(actual, spec.PluralCategories)
		if !validCategories && !contains(spec.PluralCategories, "zero") {
			withZero := append(append([]string(nil), spec.PluralCategories...), "zero")
			validCategories = sameSet(actual, withZero)
		}
		if !validCategories {
			return fmt.Errorf("%s plural %q categories %v; expected %v (optional zero)", code, key, mapKeys(categories), spec.PluralCategories)
		}
		for category, value := range categories {
			if strings.TrimSpace(value) == "" {
				return fmt.Errorf("%s plural %q category %q is empty", code, key, category)
			}
			if positionalVerbPattern.MatchString(value) {
				return fmt.Errorf("%s plural %q category %q contains a positional format verb", code, key, category)
			}
		}
		base := pluralVariables(english[key])
		for _, category := range spec.PluralCategories {
			value, ok := categories[category]
			if !ok {
				return fmt.Errorf("%s plural %q is missing category %q", code, key, category)
			}
			if !sameSet(base, pluralVariables(map[string]string{category: value})) {
				return fmt.Errorf("%s plural %q category %q placeholders do not match English (excluding optional {count})", code, key, category)
			}
		}
		if zero, ok := categories["zero"]; ok {
			if !sameSet(base, pluralVariables(map[string]string{"zero": zero})) {
				return fmt.Errorf("%s plural %q category zero placeholders do not match English (excluding optional {count})", code, key)
			}
		}
	}
	for key := range english {
		if _, ok := locale[key]; !ok {
			return fmt.Errorf("%s plural key %q is missing", code, key)
		}
	}
	return nil
}

func pluralVariables(categories map[string]string) []string {
	variables := map[string]bool{}
	for _, value := range categories {
		for _, variable := range interpVarPattern.FindAllString(value, -1) {
			if variable != "{count}" {
				variables[variable] = true
			}
		}
	}
	return mapKeys(variables)
}

func diffKeys(a, b map[string]string) []string {
	missing := make([]string, 0)
	for key := range a {
		if _, ok := b[key]; !ok {
			missing = append(missing, key)
		}
	}
	sort.Strings(missing)
	return missing
}

func mapKeys[T any](values map[string]T) []string {
	result := make([]string, 0, len(values))
	for key := range values {
		result = append(result, key)
	}
	sort.Strings(result)
	return result
}

func sameSet(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	set := make(map[string]bool, len(a))
	for _, value := range a {
		set[value] = true
	}
	for _, value := range b {
		if !set[value] {
			return false
		}
	}
	return true
}

func contains(values []string, wanted string) bool {
	for _, value := range values {
		if value == wanted {
			return true
		}
	}
	return false
}
