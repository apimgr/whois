package i18n

import (
	"embed"
	"encoding/json"
	"strings"
)

//go:embed locales/*.json
var localeFS embed.FS

// Supported is the list of language codes supported by this package.
var Supported = []string{"en", "es", "zh", "fr", "ar", "de", "ja"}

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
	if header == "" {
		return "en"
	}
	for _, segment := range strings.Split(header, ",") {
		segment = strings.TrimSpace(segment)
		if segment == "" {
			continue
		}
		// Strip quality value (e.g. "en-US;q=0.9" → "en-US")
		tag := strings.SplitN(segment, ";", 2)[0]
		tag = strings.TrimSpace(tag)
		// Try exact match first
		lower := strings.ToLower(tag)
		if IsSupported(lower) {
			return lower
		}
		// Try base language (e.g. "en-US" → "en")
		base := strings.SplitN(lower, "-", 2)[0]
		if IsSupported(base) {
			return base
		}
	}
	return "en"
}

// IsSupported reports whether the given language code is in the Supported list.
func IsSupported(lang string) bool {
	for _, s := range Supported {
		if s == lang {
			return true
		}
	}
	return false
}
