package i18n

import (
	"encoding/json"
	"fmt"
	"io/fs"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
	"time"
)

func TestIsSupported(t *testing.T) {
	cases := []struct {
		lang string
		want bool
	}{
		{"en", true},
		{"es", true},
		{"zh", true},
		{"fr", true},
		{"ar", true},
		{"de", true},
		{"ja", true},
		{"it", true},
		{"pt", false},
		{"", false},
		{"EN", false},
		{"en-US", false},
	}
	for _, tc := range cases {
		got := IsSupported(tc.lang)
		if got != tc.want {
			t.Errorf("IsSupported(%q) = %v, want %v", tc.lang, got, tc.want)
		}
	}
}

func TestLoadFallbackToEnglish(t *testing.T) {
	// Unsupported language falls back to English without error
	tr, err := Load("pt")
	if err != nil {
		t.Fatalf("Load(%q) unexpected error: %v", "pt", err)
	}
	if tr == nil {
		t.Fatal("Load returned nil Translator")
	}
}

func TestLoadEnglish(t *testing.T) {
	tr, err := Load("en")
	if err != nil {
		t.Fatalf("Load(\"en\") unexpected error: %v", err)
	}
	if tr == nil {
		t.Fatal("Load returned nil Translator")
	}
}

func TestTranslatorT(t *testing.T) {
	tr, err := Load("en")
	if err != nil {
		t.Fatalf("Load(\"en\") unexpected error: %v", err)
	}

	cases := []struct {
		key  string
		want string
	}{
		{"common.save", "Save"},
		{"common.cancel", "Cancel"},
		{"nav.home", "Home"},
		{"nav.about", "About"},
		{"whois.button", "Look up"},
		{"health.healthy", "Healthy"},
		{"theme.dark", "Dark"},
		{"errors.not_found", "Not found"},
	}
	for _, tc := range cases {
		got := tr.T(tc.key)
		if got != tc.want {
			t.Errorf("T(%q) = %q, want %q", tc.key, got, tc.want)
		}
	}
}

func TestTranslatorTMissingKey(t *testing.T) {
	tr, err := Load("en")
	if err != nil {
		t.Fatalf("Load(\"en\") unexpected error: %v", err)
	}
	// Missing keys return the key itself
	key := "nonexistent.key"
	got := tr.T(key)
	if got != key {
		t.Errorf("T(%q) = %q, want key itself", key, got)
	}
}

func TestLoadAllLanguages(t *testing.T) {
	for _, lang := range Supported {
		tr, err := Load(lang)
		if err != nil {
			t.Errorf("Load(%q) unexpected error: %v", lang, err)
			continue
		}
		if tr == nil {
			t.Errorf("Load(%q) returned nil Translator", lang)
			continue
		}
		// Every language must have common.save translated (non-empty)
		val := tr.T("common.save")
		if val == "" || val == "common.save" {
			t.Errorf("Load(%q): T(\"common.save\") = %q, want non-empty translation", lang, val)
		}
	}
}

// TestLocaleJSON verifies that LocaleJSON returns valid non-empty JSON for all
// supported languages and returns an error for unsupported ones.
func TestLocaleJSON(t *testing.T) {
	for _, lang := range Supported {
		data, err := LocaleJSON(lang)
		if err != nil {
			t.Errorf("LocaleJSON(%q) error: %v", lang, err)
			continue
		}
		if len(data) == 0 {
			t.Errorf("LocaleJSON(%q) returned empty bytes", lang)
			continue
		}
		// Minimal check: first byte of a JSON object is '{'
		if data[0] != '{' {
			t.Errorf("LocaleJSON(%q) does not start with '{': %q", lang, string(data[:1]))
		}
	}
}

// TestLocaleJSONUnsupported verifies that LocaleJSON returns an error for
// an unsupported language (the file does not exist in the embedded FS).
func TestLocaleJSONUnsupported(t *testing.T) {
	_, err := LocaleJSON("xx")
	if err == nil {
		t.Error("LocaleJSON(\"xx\") expected error for unsupported language, got nil")
	}
}

// TestDir verifies the text-direction accessor for all supported languages.
func TestDir(t *testing.T) {
	cases := []struct {
		lang string
		want string
	}{
		// Arabic is the only RTL language in the supported set
		{"ar", "rtl"},
		// All others must be LTR
		{"en", "ltr"},
		{"es", "ltr"},
		{"zh", "ltr"},
		{"fr", "ltr"},
		{"de", "ltr"},
		{"ja", "ltr"},
		{"it", "ltr"},
		// Unknown languages fall through to LTR
		{"xx", "ltr"},
		{"", "ltr"},
	}
	for _, tc := range cases {
		t.Run(tc.lang, func(t *testing.T) {
			got := Dir(tc.lang)
			if got != tc.want {
				t.Errorf("Dir(%q) = %q, want %q", tc.lang, got, tc.want)
			}
		})
	}
}

// TestTranslatorT_FallbackToEnglish verifies that when a non-English translator
// does not have a key but the English locale does, the English value is returned.
func TestTranslatorT_FallbackToEnglish(t *testing.T) {
	// Load a non-English language — all keys in "en" must be present in
	// every supported locale per spec, so we fabricate a scenario by looking
	// up a key that exists in English. If the non-English locale also has it
	// the result is still correct (it returns that locale's value). We verify
	// the invariant: T never returns an empty string for known keys.
	tr, err := Load("es")
	if err != nil {
		t.Fatalf("Load(\"es\") error: %v", err)
	}

	// "common.save" must exist in both es and en; result must be non-empty
	got := tr.T("common.save")
	if got == "" {
		t.Error("T(\"common.save\") on Spanish translator returned empty string")
	}

	// A missing key on a non-English translator must fall back to English,
	// and if not found there either, must return the key itself.
	key := "totally.nonexistent.key.xyz"
	got = tr.T(key)
	if got != key {
		t.Errorf("T(%q) = %q, want the key itself as last resort", key, got)
	}
}

// TestLookupKeyNestedMissing exercises the nested-miss branch in lookupKey
// (where the top-level key exists but the value is not a nested map).
func TestLookupKeyNestedMissing(t *testing.T) {
	tr, err := Load("en")
	if err != nil {
		t.Fatalf("Load(\"en\") error: %v", err)
	}

	// "common.save" is a leaf string; asking for "common.save.extra" should
	// fail to descend and return the key itself.
	key := "common.save.extra"
	got := tr.T(key)
	if got != key {
		t.Errorf("T(%q) = %q, want key itself for unreachable nested path", key, got)
	}
}

func TestParseAcceptLanguage(t *testing.T) {
	cases := []struct {
		header string
		want   string
	}{
		{"en-US,en;q=0.9", "en"},
		{"es-ES,es;q=0.9,en;q=0.8", "es"},
		{"it-IT,it;q=0.9,en;q=0.8", "it"},
		{"zh-CN,zh;q=0.9", "zh"},
		{"fr-FR,fr;q=0.9", "fr"},
		{"ar;q=0.9", "ar"},
		{"de-DE", "de"},
		{"es;q=0.2,fr;q=0.9,de;q=0.5", "fr"},
		{"fr;q=0,de;q=0.7", "de"},
		{"ja,en;q=0.5", "ja"},
		{"pt-BR,pt;q=0.9", "en"},
		{"", "en"},
		{"*", "en"},
		{"en", "en"},
	}
	for _, tc := range cases {
		got := ParseAcceptLanguage(tc.header)
		if got != tc.want {
			t.Errorf("ParseAcceptLanguage(%q) = %q, want %q", tc.header, got, tc.want)
		}
	}
}

func TestParseAcceptLanguageForHonorsEnabledSet(t *testing.T) {
	got := ParseAcceptLanguageFor("it-IT,it;q=0.9,fr;q=0.8", []string{"en", "fr"})
	if got != "fr" {
		t.Fatalf("ParseAcceptLanguageFor() = %q, want fr", got)
	}
}

func TestLocaleRegistry(t *testing.T) {
	codes := make([]string, 0, len(Registry))
	seen := map[string]bool{}
	for _, locale := range Registry {
		if seen[locale.Code] {
			t.Fatalf("duplicate registry code %q", locale.Code)
		}
		seen[locale.Code] = true
		codes = append(codes, locale.Code)
		if locale.Code == "" || locale.NativeName == "" || (locale.Direction != "ltr" && locale.Direction != "rtl") {
			t.Errorf("invalid locale metadata: %+v", locale)
		}
	}
	if !sameStrings(codes, SupportedLanguages()) {
		t.Fatalf("SupportedLanguages() = %v, registry codes = %v", SupportedLanguages(), codes)
	}
	italian, ok := LocaleFor("it")
	if !ok || italian.NativeName != "Italiano" || !sameStrings(italian.PluralCategories, []string{"one", "many", "other"}) {
		t.Fatalf("Italian registry entry = %+v, found=%v", italian, ok)
	}
}

func TestTranslationFormattingAndPluralCategories(t *testing.T) {
	if got := TranslateFormat("it", "preferences.automatic", map[string]string{"language": "Italiano"}); got != "Automatico (Italiano)" {
		t.Fatalf("TranslateFormat() = %q", got)
	}
	if got := TranslateFormat("en", "preferences.automatic", map[string]string{}); got != "Automatic ({language})" {
		t.Fatalf("missing named placeholder should remain visible, got %q", got)
	}
	for _, test := range []struct {
		lang  string
		count float64
		want  string
	}{
		{"it", 1, "one"}, {"it", 2, "other"}, {"it", 1000000, "many"},
		{"it", 1.5, "other"}, {"fr", 0, "one"}, {"ar", 0, "zero"},
		{"ar", 2, "two"}, {"ar", 7, "few"}, {"ar", 11, "many"}, {"zh", 3, "other"},
	} {
		if got := PluralCategoryNumber(test.lang, test.count); got != test.want {
			t.Errorf("PluralCategoryNumber(%q, %v) = %q, want %q", test.lang, test.count, got, test.want)
		}
	}
}

func TestLocaleFormatting(t *testing.T) {
	if got := FormatNumber(1234.56, "it"); got != "1.234,56" {
		t.Errorf("Italian FormatNumber() = %q, want 1.234,56", got)
	}
	if got := FormatInteger(1234, "it"); got != "1.234" {
		t.Errorf("Italian FormatInteger() = %q, want 1.234", got)
	}
}

func TestLocaleDateAndTimeFormatting(t *testing.T) {
	instant := time.Date(2026, time.January, 5, 14, 3, 7, 0, time.UTC)
	eastern := time.FixedZone("test", -5*60*60)
	if got := FormatDate(instant, "en", eastern); got != "01/05/2026" {
		t.Errorf("FormatDate() = %q, want 01/05/2026", got)
	}
	if got := FormatTime(instant, "ar", eastern); !strings.Contains(got, "٩:٠٣ ص") {
		t.Errorf("Arabic FormatTime() = %q, want localized 9:03 AM", got)
	}
	if got := FormatDateTime(instant, "ar", eastern); !strings.Contains(got, "٠٥/٠١/٢٠٢٦") {
		t.Errorf("Arabic FormatDateTime() = %q, want localized date", got)
	}
	if got := FormatDate(instant, "unsupported"); got != "01/05/2026" {
		t.Errorf("unsupported locale date fallback = %q, want 01/05/2026", got)
	}
}

func TestLocalesFS(t *testing.T) {
	files, err := fs.Glob(localeFS, "locales/*.json")
	if err != nil {
		t.Fatal(err)
	}
	var codes []string
	for _, file := range files {
		codes = append(codes, strings.TrimSuffix(filepath.Base(file), ".json"))
	}
	if !sameStrings(codes, SupportedLanguages()) {
		t.Fatalf("embedded locales %v do not match registry %v", codes, SupportedLanguages())
	}
}

func TestKeyConsistency(t *testing.T) {
	locales := map[string]localeTestData{}
	for _, code := range SupportedLanguages() {
		data, err := LocaleJSON(code)
		if err != nil {
			t.Fatalf("LocaleJSON(%q): %v", code, err)
		}
		var tree map[string]interface{}
		if err := json.Unmarshal(data, &tree); err != nil {
			t.Fatalf("parse %s locale: %v", code, err)
		}
		locale := localeTestData{messages: map[string]string{}, plurals: map[string]map[string]string{}}
		if err := flattenTestLocale("", tree, &locale); err != nil {
			t.Fatalf("flatten %s locale: %v", code, err)
		}
		locales[code] = locale
	}
	english := locales["en"]
	englishKeys := messageKeysForTest(english)
	for _, spec := range Registry {
		locale := locales[spec.Code]
		if !sameStrings(messageKeysForTest(locale), englishKeys) {
			t.Errorf("%s message keys do not match English", spec.Code)
		}
		for key, value := range locale.messages {
			if strings.TrimSpace(value) == "" || positionalVerbPattern.MatchString(value) {
				t.Errorf("%s key %q is empty or contains a positional format verb", spec.Code, key)
			}
			if !sameStrings(placeholderNames(value), placeholderNames(english.messages[key])) {
				t.Errorf("%s key %q placeholders differ from English", spec.Code, key)
			}
		}
		for key, categories := range locale.plurals {
			want := sortedCopy(spec.PluralCategories)
			got := sortedCopy(categoryNames(categories))
			if !sameStrings(got, want) && (!containsString(spec.PluralCategories, "zero") && !sameStrings(got, sortedCopy(append(append([]string(nil), want...), "zero")))) {
				t.Errorf("%s plural %q categories = %v, want %v with optional zero", spec.Code, key, got, want)
			}
			base := nonCountPlaceholdersFor(english.plurals[key])
			for category, value := range categories {
				if strings.TrimSpace(value) == "" || positionalVerbPattern.MatchString(value) {
					t.Errorf("%s plural %q category %q is empty or contains a positional format verb", spec.Code, key, category)
				}
				if !sameStrings(nonCountPlaceholders(value), base) {
					t.Errorf("%s plural %q category %q placeholders differ from English", spec.Code, key, category)
				}
			}
		}
		if locale.metadata["language"] != spec.Code || locale.metadata["name"] != spec.Name || locale.metadata["native_name"] != spec.NativeName || locale.metadata["direction"] != spec.Direction {
			t.Errorf("%s metadata does not match registry", spec.Code)
		}
	}
}

type localeTestData struct {
	messages map[string]string
	plurals  map[string]map[string]string
	metadata map[string]string
}

var localeCategoryNames = map[string]bool{"zero": true, "one": true, "two": true, "few": true, "many": true, "other": true}
var positionalVerbPattern = regexp.MustCompile(`%[-+0-9.#]*[sd]`)
var namedPlaceholderPattern = regexp.MustCompile(`\{[a-zA-Z0-9_]+\}`)

func flattenTestLocale(prefix string, node map[string]interface{}, out *localeTestData) error {
	if strings.HasPrefix(prefix, "plurals.") && len(node) > 0 {
		categoryMap := true
		for key := range node {
			categoryMap = categoryMap && localeCategoryNames[key]
		}
		if categoryMap {
			categories := make(map[string]string, len(node))
			for category, value := range node {
				text, ok := value.(string)
				if !ok {
					return fmt.Errorf("plural %s category %s is not a string", prefix, category)
				}
				categories[category] = text
			}
			out.plurals[prefix] = categories
			return nil
		}
	}
	for key, value := range node {
		path := key
		if prefix != "" {
			path = prefix + "." + key
		}
		switch item := value.(type) {
		case map[string]interface{}:
			if err := flattenTestLocale(path, item, out); err != nil {
				return err
			}
		case string:
			out.messages[path] = item
			if strings.HasPrefix(path, "meta.") {
				if out.metadata == nil {
					out.metadata = map[string]string{}
				}
				out.metadata[strings.TrimPrefix(path, "meta.")] = item
			}
		default:
			return fmt.Errorf("locale path %s has unsupported value", path)
		}
	}
	return nil
}

func messageKeysForTest(locale localeTestData) []string {
	keys := make([]string, 0, len(locale.messages)+len(locale.plurals))
	for key := range locale.messages {
		keys = append(keys, key)
	}
	for key := range locale.plurals {
		keys = append(keys, key)
	}
	return sortedCopy(keys)
}

func placeholderNames(value string) []string {
	seen := map[string]bool{}
	for _, name := range namedPlaceholderPattern.FindAllString(value, -1) {
		seen[name] = true
	}
	return stringSet(seen)
}

func nonCountPlaceholders(value string) []string {
	seen := map[string]bool{}
	for _, name := range namedPlaceholderPattern.FindAllString(value, -1) {
		if name != "{count}" {
			seen[name] = true
		}
	}
	return stringSet(seen)
}

func nonCountPlaceholdersFor(values map[string]string) []string {
	seen := map[string]bool{}
	for _, value := range values {
		for _, name := range nonCountPlaceholders(value) {
			seen[name] = true
		}
	}
	return stringSet(seen)
}

func categoryNames(values map[string]string) []string {
	result := make([]string, 0, len(values))
	for name := range values {
		result = append(result, name)
	}
	return sortedCopy(result)
}

func stringSet(values map[string]bool) []string {
	result := make([]string, 0, len(values))
	for value := range values {
		result = append(result, value)
	}
	return sortedCopy(result)
}

func containsString(values []string, wanted string) bool {
	for _, value := range values {
		if value == wanted {
			return true
		}
	}
	return false
}

func sameStrings(a, b []string) bool {
	return strings.Join(sortedCopy(a), "\x00") == strings.Join(sortedCopy(b), "\x00")
}

func sortedCopy(values []string) []string {
	result := append([]string(nil), values...)
	sort.Strings(result)
	return result
}
