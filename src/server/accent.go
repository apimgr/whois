package server

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math"
	"net/http"
	"strconv"
	"strings"
)

type rgbColor struct {
	r float64
	g float64
	b float64
}

func accentStylesheetURL(configured string) bool {
	_, ok := parseHexColor(configured)
	return ok
}

func parseHexColor(value string) (rgbColor, bool) {
	value = strings.TrimSpace(value)
	if !strings.HasPrefix(value, "#") {
		return rgbColor{}, false
	}
	value = strings.TrimPrefix(value, "#")
	if len(value) != 6 {
		return rgbColor{}, false
	}
	decoded, err := hex.DecodeString(value)
	if err != nil || len(decoded) != 3 {
		return rgbColor{}, false
	}
	return rgbColor{float64(decoded[0]) / 255, float64(decoded[1]) / 255, float64(decoded[2]) / 255}, true
}

func (s *Server) handleAccentCSS(w http.ResponseWriter, r *http.Request) {
	base, ok := parseHexColor(s.config.Web.UI.Accent)
	if !ok {
		http.NotFound(w, r)
		return
	}
	dark := accentWithContrast(base, rgbColor{40.0 / 255, 42.0 / 255, 54.0 / 255}, true)
	light := accentWithContrast(base, rgbColor{1, 1, 1}, false)
	body := fmt.Sprintf(`:root{--color-primary:%s;--color-primary-bg:rgba(%s,.15)}
html.theme-light{--color-primary:%s;--color-primary-bg:rgba(%s,.12)}
@media(prefers-color-scheme:light){html.theme-auto{--color-primary:%s;--color-primary-bg:rgba(%s,.12)}}
`, colorHex(dark), colorRGB(dark), colorHex(light), colorRGB(light), colorHex(light), colorRGB(light))
	content := []byte(body)
	sum := sha256.Sum256(content)
	etag := `"` + hex.EncodeToString(sum[:]) + `"`
	w.Header().Set("Content-Type", "text/css; charset=utf-8")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("ETag", etag)
	if r.Header.Get("If-None-Match") == etag {
		w.WriteHeader(http.StatusNotModified)
		return
	}
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(content)
}

func accentWithContrast(color, background rgbColor, lighten bool) rgbColor {
	hue, saturation, lightness := rgbToHSL(color)
	if contrastRatio(color, background) >= 4.5 {
		return color
	}
	for step := 1; step <= 100; step++ {
		candidateLightness := lightness + float64(step)/100
		if !lighten {
			candidateLightness = lightness - float64(step)/100
		}
		candidate := hslToRGB(hue, saturation, math.Max(0, math.Min(1, candidateLightness)))
		if contrastRatio(candidate, background) >= 4.5 {
			return candidate
		}
	}
	if lighten {
		return hslToRGB(hue, saturation, 1)
	}
	return hslToRGB(hue, saturation, 0)
}

func rgbToHSL(c rgbColor) (hue, saturation, lightness float64) {
	max := math.Max(c.r, math.Max(c.g, c.b))
	min := math.Min(c.r, math.Min(c.g, c.b))
	lightness = (max + min) / 2
	if max == min {
		return 0, 0, lightness
	}
	delta := max - min
	if lightness > .5 {
		saturation = delta / (2 - max - min)
	} else {
		saturation = delta / (max + min)
	}
	switch max {
	case c.r:
		hue = (c.g - c.b) / delta
		if c.g < c.b {
			hue += 6
		}
	case c.g:
		hue = (c.b-c.r)/delta + 2
	default:
		hue = (c.r-c.g)/delta + 4
	}
	hue /= 6
	return hue, saturation, lightness
}

func hslToRGB(hue, saturation, lightness float64) rgbColor {
	if saturation == 0 {
		return rgbColor{lightness, lightness, lightness}
	}
	q := lightness * (1 + saturation)
	if lightness >= .5 {
		q = lightness + saturation - lightness*saturation
	}
	p := 2*lightness - q
	return rgbColor{hueToRGB(p, q, hue+1.0/3), hueToRGB(p, q, hue), hueToRGB(p, q, hue-1.0/3)}
}

func hueToRGB(p, q, t float64) float64 {
	if t < 0 {
		t++
	}
	if t > 1 {
		t--
	}
	if t < 1.0/6 {
		return p + (q-p)*6*t
	}
	if t < 1.0/2 {
		return q
	}
	if t < 2.0/3 {
		return p + (q-p)*(2.0/3-t)*6
	}
	return p
}

func contrastRatio(foreground, background rgbColor) float64 {
	a, b := relativeLuminance(foreground), relativeLuminance(background)
	if a < b {
		a, b = b, a
	}
	return (a + .05) / (b + .05)
}

func relativeLuminance(c rgbColor) float64 {
	linear := func(value float64) float64 {
		if value <= .04045 {
			return value / 12.92
		}
		return math.Pow((value+.055)/1.055, 2.4)
	}
	return .2126*linear(c.r) + .7152*linear(c.g) + .0722*linear(c.b)
}

func colorHex(c rgbColor) string {
	return fmt.Sprintf("#%02x%02x%02x", channelByte(c.r), channelByte(c.g), channelByte(c.b))
}

func colorRGB(c rgbColor) string {
	return strconv.Itoa(channelByte(c.r)) + "," + strconv.Itoa(channelByte(c.g)) + "," + strconv.Itoa(channelByte(c.b))
}

func channelByte(value float64) int {
	return int(math.Round(math.Max(0, math.Min(1, value)) * 255))
}
