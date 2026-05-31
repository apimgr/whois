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
