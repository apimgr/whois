// Package format provides shared, locale-aware human-readable values.
package format

import (
	"math"
	"strings"
	"time"
	"unicode"

	"github.com/apimgr/whois/src/common/i18n"
)

// Duration returns a localized duration using at most two adjacent units.
func Duration(value time.Duration, lang string) string {
	seconds := int(math.Round(math.Abs(value.Seconds())))
	if seconds < 60 {
		return i18n.TranslatePlural(lang, "plurals.duration.seconds", seconds)
	}
	minutes := seconds / 60
	if minutes < 60 {
		return join(i18n.TranslatePlural(lang, "plurals.duration.minutes", minutes), seconds%60, "plurals.duration.seconds", lang)
	}
	hours := minutes / 60
	if hours < 24 {
		return join(i18n.TranslatePlural(lang, "plurals.duration.hours", hours), minutes%60, "plurals.duration.minutes", lang)
	}
	days := hours / 24
	return join(i18n.TranslatePlural(lang, "plurals.duration.days", days), hours%24, "plurals.duration.hours", lang)
}

func join(first string, remainder int, key, lang string) string {
	if remainder == 0 {
		return first
	}
	return first + " " + i18n.TranslatePlural(lang, key, remainder)
}

// Size returns a localized byte size using binary units and at most one decimal.
func Size(bytes uint64, lang string) string {
	keys := [...]string{"bytes", "kilobytes", "megabytes", "gigabytes", "terabytes"}
	value := float64(bytes)
	unit := 0
	for value >= 1024 && unit < len(keys)-1 {
		value /= 1024
		unit++
	}
	if unit == 0 {
		return i18n.TranslatePlural(lang, "plurals.size."+keys[unit], int(bytes))
	}
	value = math.Round(value*10) / 10
	return i18n.TranslatePluralNumber(lang, "plurals.size."+keys[unit], value, map[string]string{"count": trimDecimal(i18n.FormatNumber(value, lang))})
}

// Count returns an integer with locale-aware grouping and digits.
func Count(value int64, lang string) string {
	if value > int64(^uint(0)>>1) {
		return i18n.FormatNumber(float64(value), lang)
	}
	if value < -int64(^uint(0)>>1)-1 {
		return i18n.FormatNumber(float64(value), lang)
	}
	return i18n.FormatInteger(int(value), lang)
}

func trimDecimal(value string) string {
	for strings.HasSuffix(value, "0") {
		value = strings.TrimSuffix(value, "0")
	}
	runes := []rune(value)
	for index := len(runes) - 1; index >= 0; index-- {
		if unicode.IsDigit(runes[index]) {
			return string(runes[:index+1])
		}
	}
	return value
}
