package i18n

import (
	"embed"
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"golang.org/x/text/feature/plural"
	"golang.org/x/text/language"
	"golang.org/x/text/message"
)

//go:embed locales/*.json
var localeFS embed.FS

// Locale describes one embedded language and the CLDR rules used to format it.
type Locale struct {
	Code             string
	Name             string
	NativeName       string
	Direction        string
	PluralCategories []string
}

// Registry is the single source of language metadata for all binaries.
var Registry = []Locale{
	{Code: "en", Name: "English", NativeName: "English", Direction: "ltr", PluralCategories: []string{"one", "other"}},
	{Code: "es", Name: "Spanish", NativeName: "Español", Direction: "ltr", PluralCategories: []string{"one", "other"}},
	{Code: "zh", Name: "Chinese", NativeName: "中文", Direction: "ltr", PluralCategories: []string{"other"}},
	{Code: "fr", Name: "French", NativeName: "Français", Direction: "ltr", PluralCategories: []string{"one", "other"}},
	{Code: "ar", Name: "Arabic", NativeName: "العربية", Direction: "rtl", PluralCategories: []string{"zero", "one", "two", "few", "many", "other"}},
	{Code: "de", Name: "German", NativeName: "Deutsch", Direction: "ltr", PluralCategories: []string{"one", "other"}},
	{Code: "ja", Name: "Japanese", NativeName: "日本語", Direction: "ltr", PluralCategories: []string{"other"}},
	{Code: "it", Name: "Italian", NativeName: "Italiano", Direction: "ltr", PluralCategories: []string{"one", "many", "other"}},
}

// Supported is derived from Registry so every binary uses the same languages.
var Supported = supportedLanguageCodes()

func supportedLanguageCodes() []string {
	codes := make([]string, len(Registry))
	for index, locale := range Registry {
		codes[index] = locale.Code
	}
	return codes
}

// LocaleFor returns registered metadata for a language code.
func LocaleFor(code string) (Locale, bool) {
	for _, locale := range Registry {
		if locale.Code == code {
			return locale, true
		}
	}
	return Locale{}, false
}

// SupportedLanguages returns a copy of the registered language codes.
func SupportedLanguages() []string {
	return supportedLanguageCodes()
}

// Translator holds the active language code and its parsed locale data.
type Translator struct {
	lang string
	data map[string]interface{}
}

// loadLocale reads and parses the JSON locale file for the given language code.
func loadLocale(lang string) (map[string]interface{}, error) {
	raw, err := localeFS.ReadFile("locales/" + lang + ".json")
	if err != nil {
		return nil, err
	}
	var data map[string]interface{}
	if err := json.Unmarshal(raw, &data); err != nil {
		return nil, err
	}
	return data, nil
}

// Load returns a Translator for the given language code.
// If the language is not supported, it falls back to "en".
func Load(lang string) (*Translator, error) {
	if !IsSupported(lang) {
		lang = "en"
	}
	data, err := loadLocale(lang)
	if err != nil {
		return nil, err
	}
	return &Translator{lang: lang, data: data}, nil
}

// T looks up a translation by dot-notation key (e.g. "common.save").
// If the key is missing in the active language, it falls back to "en".
// If still not found, it returns the key itself.
func (t *Translator) T(key string) string {
	if val := lookupKey(t.data, key); val != "" {
		return val
	}
	if t.lang != "en" {
		enData, err := loadLocale("en")
		if err == nil {
			if val := lookupKey(enData, key); val != "" {
				return val
			}
		}
	}
	return key
}

// TF translates a key and literally replaces named {token} placeholders.
func (t *Translator) TF(key string, args map[string]string) string {
	return TranslateFormat(t.lang, key, args)
}

// Translate returns a translated message, falling back to English and then the key.
func Translate(lang, key string) string {
	translator, err := Load(lang)
	if err != nil {
		return key
	}
	return translator.T(key)
}

// TranslateFormat performs literal named-placeholder replacement. Missing
// placeholders remain visible and extra arguments are ignored.
func TranslateFormat(lang, key string, args map[string]string) string {
	value := Translate(lang, key)
	for name, replacement := range args {
		value = strings.ReplaceAll(value, "{"+name+"}", replacement)
	}
	return value
}

var pluralKeys = map[plural.Form]string{
	plural.Zero:  "zero",
	plural.One:   "one",
	plural.Two:   "two",
	plural.Few:   "few",
	plural.Many:  "many",
	plural.Other: "other",
}

// PluralCategory returns the CLDR cardinal category for an integer value.
func PluralCategory(lang string, count int) string {
	return PluralCategoryNumber(lang, float64(count))
}

// PluralCategoryNumber returns the CLDR cardinal category for a decimal value.
func PluralCategoryNumber(lang string, value float64) string {
	if !IsSupported(lang) {
		lang = "en"
	}
	tag, err := language.Parse(lang)
	if err != nil {
		tag = language.English
	}
	i, v, w, f, t := pluralOperands(value)
	if lang == "it" && v == 0 && i >= 1_000_000 && i%1_000_000 == 0 {
		return "many"
	}
	return pluralKeys[plural.Cardinal.MatchPlural(tag, i, v, w, f, t)]
}

func pluralOperands(value float64) (i, v, w, f, t int) {
	if value < 0 {
		value = -value
	}
	parts := strings.SplitN(strconv.FormatFloat(value, 'f', -1, 64), ".", 2)
	i, _ = strconv.Atoi(parts[0])
	if len(parts) == 1 {
		return i, 0, 0, 0, 0
	}
	fraction := parts[1]
	v = len(fraction)
	f, _ = strconv.Atoi(fraction)
	trimmed := strings.TrimRight(fraction, "0")
	w = len(trimmed)
	t, _ = strconv.Atoi(trimmed)
	return i, v, w, f, t
}

// TranslatePlural chooses a CLDR category and formats {count} for the locale.
func TranslatePlural(lang, key string, count int) string {
	return TranslatePluralFormat(lang, key, count, nil)
}

// TranslatePluralFormat chooses a CLDR category and replaces named arguments.
// A caller-supplied count supports a locale-formatted decimal value.
func TranslatePluralFormat(lang, key string, count int, args map[string]string) string {
	return TranslatePluralCategory(lang, key, PluralCategory(lang, count), withCount(lang, count, args))
}

// TranslatePluralNumber supports fractional values while preserving CLDR operands.
func TranslatePluralNumber(lang, key string, value float64, args map[string]string) string {
	category := PluralCategoryNumber(lang, value)
	return TranslatePluralCategory(lang, key, category, withFormattedCount(lang, value, args))
}

// TranslatePluralCategory selects a supplied CLDR category and formats named arguments.
func TranslatePluralCategory(lang, key, category string, args map[string]string) string {
	translator, err := Load(lang)
	if err != nil {
		return key
	}
	node, ok := lookupValue(translator.data, key).(map[string]interface{})
	if !ok && translator.lang != "en" {
		english, loadErr := Load("en")
		if loadErr == nil {
			node, ok = lookupValue(english.data, key).(map[string]interface{})
		}
	}
	if !ok {
		return key
	}
	value, found := node[category].(string)
	if category == "zero" && !found {
		value, found = node[pluralKeys[plural.Cardinal.MatchPlural(language.English, 0, 0, 0, 0, 0)]].(string)
	}
	if !found {
		value, found = node["other"].(string)
	}
	if !found {
		return key
	}
	return replaceNamed(value, args)
}

// Pluralize retains the key/count/language argument order used in AI.md's example.
func Pluralize(key string, count int, lang string) string {
	return TranslatePlural(lang, key, count)
}

func withCount(lang string, count int, args map[string]string) map[string]string {
	return withFormattedCount(lang, float64(count), args)
}

func withFormattedCount(lang string, count float64, args map[string]string) map[string]string {
	formatted := FormatInteger(int(count), lang)
	if count != float64(int(count)) {
		formatted = FormatNumber(count, lang)
	}
	result := make(map[string]string, len(args)+1)
	for key, value := range args {
		result[key] = value
	}
	if _, exists := result["count"]; !exists {
		result["count"] = formatted
	}
	return result
}

func replaceNamed(value string, args map[string]string) string {
	for name, replacement := range args {
		value = strings.ReplaceAll(value, "{"+name+"}", replacement)
	}
	return value
}

func lookupValue(data map[string]interface{}, key string) interface{} {
	parts := strings.Split(key, ".")
	var value interface{} = data
	for _, part := range parts {
		nested, ok := value.(map[string]interface{})
		if !ok {
			return nil
		}
		value, ok = nested[part]
		if !ok {
			return nil
		}
	}
	return value
}

// FormatNumber formats a number with the locale's grouping and decimal marks.
func FormatNumber(value float64, lang string) string {
	tag, err := language.Parse(lang)
	if err != nil || !IsSupported(lang) {
		tag = language.English
	}
	return localizedDigits(message.NewPrinter(tag).Sprintf("%.2f", value), lang)
}

// FormatInteger formats an integer with the locale's grouping and numerals.
func FormatInteger(value int, lang string) string {
	tag, err := language.Parse(lang)
	if err != nil || !IsSupported(lang) {
		tag = language.English
	}
	return localizedDigits(message.NewPrinter(tag).Sprintf("%d", value), lang)
}

func localizedDigits(value, lang string) string {
	translator, err := Load(lang)
	if err != nil {
		return value
	}
	digits := []rune(translator.T("format.digits"))
	if len(digits) != 10 {
		return value
	}
	for index, digit := range "0123456789" {
		value = strings.ReplaceAll(value, string(digit), string(digits[index]))
	}
	return value
}

func localizedTime(value time.Time, lang, key, fallback string, zone []*time.Location) string {
	if !IsSupported(lang) {
		lang = "en"
	}
	translator, err := Load(lang)
	if err != nil {
		return value.Format(fallback)
	}
	if len(zone) > 0 && zone[0] != nil {
		value = value.In(zone[0])
	}
	layout := translator.T(key)
	if layout == key || layout == "" {
		layout = fallback
	}
	formatted := value.Format(layout)
	if am := translator.T("format.am"); am != "format.am" {
		formatted = strings.ReplaceAll(formatted, "AM", am)
	}
	if pm := translator.T("format.pm"); pm != "format.pm" {
		formatted = strings.ReplaceAll(formatted, "PM", pm)
	}
	digits := translator.T("format.digits")
	digitRunes := []rune(digits)
	if len(digitRunes) == 10 {
		for index, digit := range "0123456789" {
			formatted = strings.ReplaceAll(formatted, string(digit), string(digitRunes[index]))
		}
	}
	return formatted
}

// FormatDate formats a date with the locale's embedded reference layout.
func FormatDate(value time.Time, lang string, zone ...*time.Location) string {
	return localizedTime(value, lang, "format.date", "01/02/2006", zone)
}

// FormatTime formats a time with the locale's embedded reference layout.
func FormatTime(value time.Time, lang string, zone ...*time.Location) string {
	return localizedTime(value, lang, "format.time", "3:04 PM", zone)
}

// FormatDateTime formats a date and time with the locale's embedded layout.
func FormatDateTime(value time.Time, lang string, zone ...*time.Location) string {
	return localizedTime(value, lang, "format.datetime", "01/02/2006 3:04 PM", zone)
}

// lookupKey traverses a nested map using dot-separated key segments.
func lookupKey(data map[string]interface{}, key string) string {
	parts := strings.SplitN(key, ".", 2)
	val, ok := data[parts[0]]
	if !ok {
		return ""
	}
	if len(parts) == 1 {
		if s, ok := val.(string); ok {
			return s
		}
		return ""
	}
	nested, ok := val.(map[string]interface{})
	if !ok {
		return ""
	}
	return lookupKey(nested, parts[1])
}

// ParseAcceptLanguage parses the Accept-Language HTTP header and returns
// the first supported language code, or "en" if none match.
func ParseAcceptLanguage(header string) string {
	return ParseAcceptLanguageFor(header, SupportedLanguages())
}

// ParseAcceptLanguageFor selects the best language from the enabled set while
// rejecting codes absent from the shared registry.
func ParseAcceptLanguageFor(header string, supported []string) string {
	if header == "" {
		return "en"
	}
	if len(supported) == 0 {
		supported = SupportedLanguages()
	}
	isAllowed := func(tag string) bool {
		for _, code := range supported {
			if strings.EqualFold(tag, code) && IsSupported(code) {
				return true
			}
		}
		return false
	}
	type candidate struct {
		tag   string
		q     float64
		index int
	}
	candidates := make([]candidate, 0)
	for index, segment := range strings.Split(header, ",") {
		segment = strings.TrimSpace(segment)
		if segment == "" {
			continue
		}
		parts := strings.Split(segment, ";")
		tag := strings.TrimSpace(parts[0])
		quality := 1.0
		for _, parameter := range parts[1:] {
			key, value, found := strings.Cut(strings.TrimSpace(parameter), "=")
			if !found || !strings.EqualFold(strings.TrimSpace(key), "q") {
				continue
			}
			parsed, err := strconv.ParseFloat(strings.TrimSpace(value), 64)
			if err != nil || parsed < 0 || parsed > 1 {
				quality = 0
			} else {
				quality = parsed
			}
			break
		}
		if tag != "" && quality > 0 {
			candidates = append(candidates, candidate{tag: tag, q: quality, index: index})
		}
	}
	sort.SliceStable(candidates, func(i, j int) bool {
		if candidates[i].q == candidates[j].q {
			return candidates[i].index < candidates[j].index
		}
		return candidates[i].q > candidates[j].q
	})
	for _, candidate := range candidates {
		// Try exact match first
		lower := strings.ToLower(candidate.tag)
		if isAllowed(lower) {
			return lower
		}
		// Try base language (e.g. "en-US" → "en")
		base := strings.SplitN(lower, "-", 2)[0]
		if isAllowed(base) {
			return base
		}
	}
	return "en"
}

// LocaleJSON returns the raw JSON bytes for the given language code.
// The caller must pass a validated language code (use IsSupported first).
func LocaleJSON(lang string) ([]byte, error) {
	if !IsSupported(lang) {
		return nil, fmt.Errorf("unsupported language %q", lang)
	}
	return localeFS.ReadFile("locales/" + lang + ".json")
}

// IsSupported reports whether the given language code is in the Supported list.
func IsSupported(lang string) bool {
	_, ok := LocaleFor(lang)
	return ok
}

// Dir returns the text directionality for the given language code.
// Arabic (ar) is RTL; all other supported languages are LTR.
func Dir(lang string) string {
	if locale, ok := LocaleFor(lang); ok {
		return locale.Direction
	}
	return "ltr"
}
