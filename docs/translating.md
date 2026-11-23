# Translating

caswhois keeps interface strings in JSON locale files under `src/common/i18n/locales/`. Supported locale files currently include Arabic, German, English, Spanish, French, Japanese, and Chinese.

## Editing a translation

Use the English locale as the key and wording reference. Preserve JSON keys and nesting, translate only user-visible strings, and keep placeholders such as `{{.Name}}` or format markers unchanged. Do not add translations by editing embedded templates directly; templates should reference translation keys.

When adding a string, add its key to each supported locale. Keep accessibility labels, errors, and instructions clear and equivalent to the English source. Arabic uses right-to-left direction; avoid embedding left-to-right punctuation assumptions in translated text.

## Review checklist

- Preserve valid JSON and the existing locale metadata.
- Keep placeholders and interpolation values intact.
- Check that button labels and form instructions remain concise.
- Verify translated strings in both light and dark themes and at mobile widths.
- Include the locale in the project translation validation workflow.

Contributions should include the locale file changes with the feature that introduces the strings.
