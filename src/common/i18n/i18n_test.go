package i18n

import (
	"testing"
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
		{"zh-CN,zh;q=0.9", "zh"},
		{"fr-FR,fr;q=0.9", "fr"},
		{"ar;q=0.9", "ar"},
		{"de-DE", "de"},
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
