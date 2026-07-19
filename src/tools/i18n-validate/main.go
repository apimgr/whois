// Command i18n-validate checks that every locale file under
// src/common/i18n/locales/ has the exact same key set as en.json,
// no empty string values, and matching {var} interpolation tokens.
// AI.md PART 30 requires this build-time check.
package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

// requiredLanguages are the 7 languages AI.md PART 30 mandates.
var requiredLanguages = []string{"en", "es", "zh", "fr", "ar", "de", "ja"}

// interpVarPattern matches {var}-style interpolation placeholders.
var interpVarPattern = regexp.MustCompile(`\{[a-zA-Z0-9_]+\}`)

func main() {
	dir := "src/common/i18n/locales"
	if len(os.Args) > 1 {
		dir = os.Args[1]
	}

	enPath := filepath.Join(dir, "en.json")
	enFlat, err := loadFlat(enPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "i18n-validate: failed to load %s: %v\n", enPath, err)
		os.Exit(1)
	}

	failed := false

	for _, lang := range requiredLanguages {
		if lang == "en" {
			continue
		}
		path := filepath.Join(dir, lang+".json")
		flat, err := loadFlat(path)
		if err != nil {
			fmt.Fprintf(os.Stderr, "i18n-validate: %s: %v\n", lang, err)
			failed = true
			continue
		}

		missing := diffKeys(enFlat, flat)
		extra := diffKeys(flat, enFlat)

		if len(missing) > 0 {
			failed = true
			fmt.Fprintf(os.Stderr, "i18n-validate: %s missing %d key(s):\n", lang, len(missing))
			for _, k := range missing {
				fmt.Fprintf(os.Stderr, "  - %s\n", k)
			}
		}
		if len(extra) > 0 {
			failed = true
			fmt.Fprintf(os.Stderr, "i18n-validate: %s has %d orphaned key(s) not in en.json:\n", lang, len(extra))
			for _, k := range extra {
				fmt.Fprintf(os.Stderr, "  - %s\n", k)
			}
		}

		for k, v := range flat {
			if strings.TrimSpace(v) == "" {
				failed = true
				fmt.Fprintf(os.Stderr, "i18n-validate: %s key %q has an empty value\n", lang, k)
			}
			enVal, ok := enFlat[k]
			if !ok {
				continue
			}
			enVars := interpVarPattern.FindAllString(enVal, -1)
			langVars := interpVarPattern.FindAllString(v, -1)
			if !sameSet(enVars, langVars) {
				failed = true
				fmt.Fprintf(os.Stderr, "i18n-validate: %s key %q interpolation vars %v do not match en %v\n", lang, k, langVars, enVars)
			}
		}
	}

	for k, v := range enFlat {
		if strings.TrimSpace(v) == "" {
			failed = true
			fmt.Fprintf(os.Stderr, "i18n-validate: en key %q has an empty value\n", k)
		}
	}

	if failed {
		fmt.Fprintln(os.Stderr, "i18n-validate: FAILED")
		os.Exit(1)
	}

	fmt.Println("i18n-validate: OK — all languages match en.json key set")
}

// loadFlat reads a locale JSON file and flattens it into dot-path keys.
func loadFlat(path string) (map[string]string, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading file: %w", err)
	}
	var tree map[string]interface{}
	if err := json.Unmarshal(raw, &tree); err != nil {
		return nil, fmt.Errorf("parsing JSON: %w", err)
	}
	flat := make(map[string]string)
	flatten("", tree, flat)
	return flat, nil
}

// flatten walks a nested map and records dot-path keys with string leaf values.
func flatten(prefix string, node map[string]interface{}, out map[string]string) {
	for k, v := range node {
		key := k
		if prefix != "" {
			key = prefix + "." + k
		}
		switch val := v.(type) {
		case map[string]interface{}:
			flatten(key, val, out)
		case string:
			out[key] = val
		default:
			out[key] = fmt.Sprintf("%v", val)
		}
	}
}

// diffKeys returns sorted keys present in a but not in b.
func diffKeys(a, b map[string]string) []string {
	var out []string
	for k := range a {
		if _, ok := b[k]; !ok {
			out = append(out, k)
		}
	}
	sort.Strings(out)
	return out
}

// sameSet reports whether two string slices contain the same elements,
// ignoring order and duplicates.
func sameSet(a, b []string) bool {
	setA := make(map[string]bool)
	for _, v := range a {
		setA[v] = true
	}
	setB := make(map[string]bool)
	for _, v := range b {
		setB[v] = true
	}
	if len(setA) != len(setB) {
		return false
	}
	for k := range setA {
		if !setB[k] {
			return false
		}
	}
	return true
}
