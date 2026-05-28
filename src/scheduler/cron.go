// Package scheduler provides built-in task scheduling
// See AI.md PART 19: SCHEDULER
package scheduler

import (
	"fmt"
	"math/bits"
	"strconv"
	"strings"
	"time"
)

// cronExpr holds pre-computed bitsets for each cron field.
// Bit N is set when N is a valid value for that field.
type cronExpr struct {
	// everyDuration is non-zero for @every expressions
	everyDuration time.Duration
	// minute: bits 0–59
	minute uint64
	// hour: bits 0–23
	hour uint32
	// dom: bits 1–31 (bit 0 unused)
	dom uint32
	// month: bits 1–12 (bit 0 unused)
	month uint16
	// dow: bits 0–6 (Sunday=0)
	dow uint8
}

// atShortcuts maps @ aliases to standard 5-field expressions.
var atShortcuts = map[string]string{
	"@yearly":   "0 0 1 1 *",
	"@annually": "0 0 1 1 *",
	"@monthly":  "0 0 1 * *",
	"@weekly":   "0 0 * * 0",
	"@daily":    "0 0 * * *",
	"@midnight": "0 0 * * *",
	"@hourly":   "0 * * * *",
}

// parseCron parses a cron schedule string and returns a cronExpr.
// Supports 5-field standard cron, @ shortcuts, and @every <duration>.
// Returns an error for invalid expressions.
func parseCron(schedule string) (cronExpr, error) {
	schedule = strings.TrimSpace(schedule)

	// Handle @every <duration>
	if strings.HasPrefix(schedule, "@every ") {
		raw := strings.TrimPrefix(schedule, "@every ")
		d, err := time.ParseDuration(strings.TrimSpace(raw))
		if err != nil {
			return cronExpr{}, fmt.Errorf("invalid @every duration %q: %w", raw, err)
		}
		if d <= 0 {
			return cronExpr{}, fmt.Errorf("@every duration must be positive, got %v", d)
		}
		return cronExpr{everyDuration: d}, nil
	}

	// Expand @ shortcuts
	if expanded, ok := atShortcuts[schedule]; ok {
		schedule = expanded
	}

	// Parse standard 5-field cron
	fields := strings.Fields(schedule)
	if len(fields) != 5 {
		return cronExpr{}, fmt.Errorf("cron expression must have 5 fields, got %d: %q", len(fields), schedule)
	}

	var expr cronExpr
	var err error

	expr.minute, err = parseField(fields[0], 0, 59)
	if err != nil {
		return cronExpr{}, fmt.Errorf("invalid minute field %q: %w", fields[0], err)
	}

	hourBits, err := parseField(fields[1], 0, 23)
	if err != nil {
		return cronExpr{}, fmt.Errorf("invalid hour field %q: %w", fields[1], err)
	}
	expr.hour = uint32(hourBits)

	domBits, err := parseField(fields[2], 1, 31)
	if err != nil {
		return cronExpr{}, fmt.Errorf("invalid DOM field %q: %w", fields[2], err)
	}
	expr.dom = uint32(domBits)

	monthBits, err := parseField(fields[3], 1, 12)
	if err != nil {
		return cronExpr{}, fmt.Errorf("invalid month field %q: %w", fields[3], err)
	}
	expr.month = uint16(monthBits)

	dowBits, err := parseField(fields[4], 0, 6)
	if err != nil {
		return cronExpr{}, fmt.Errorf("invalid DOW field %q: %w", fields[4], err)
	}
	expr.dow = uint8(dowBits)

	return expr, nil
}

// parseField parses a single cron field into a bitset.
// Supports: * (wildcard), N (single value), N-M (range), */N or N-M/N (step), and comma-separated lists.
func parseField(field string, min, max int) (uint64, error) {
	var bits uint64

	for _, part := range strings.Split(field, ",") {
		b, err := parsePart(part, min, max)
		if err != nil {
			return 0, err
		}
		bits |= b
	}

	return bits, nil
}

// parsePart parses a single non-comma cron sub-expression into a bitset.
func parsePart(part string, min, max int) (uint64, error) {
	step := 1
	base := part

	// Extract step component (e.g., */5 or 1-5/2)
	if idx := strings.Index(part, "/"); idx >= 0 {
		stepStr := part[idx+1:]
		base = part[:idx]
		s, err := strconv.Atoi(stepStr)
		if err != nil || s < 1 {
			return 0, fmt.Errorf("invalid step %q", stepStr)
		}
		step = s
	}

	var lo, hi int

	if base == "*" {
		lo, hi = min, max
	} else if idx := strings.Index(base, "-"); idx >= 0 {
		// Range: N-M
		loStr := base[:idx]
		hiStr := base[idx+1:]
		var err error
		lo, err = parseIntField(loStr, min, max)
		if err != nil {
			return 0, err
		}
		hi, err = parseIntField(hiStr, min, max)
		if err != nil {
			return 0, err
		}
		if lo > hi {
			return 0, fmt.Errorf("range start %d is greater than end %d", lo, hi)
		}
	} else {
		// Single value
		val, err := parseIntField(base, min, max)
		if err != nil {
			return 0, err
		}
		lo, hi = val, val
	}

	var result uint64
	for v := lo; v <= hi; v += step {
		result |= 1 << uint(v)
	}

	return result, nil
}

// parseIntField converts a string to an integer within [min, max].
// Also maps month and DOW names to integers.
func parseIntField(s string, min, max int) (int, error) {
	// Map month names
	s = strings.ToLower(s)
	if v, ok := monthNames[s]; ok {
		if v < min || v > max {
			return 0, fmt.Errorf("value %d out of range [%d, %d]", v, min, max)
		}
		return v, nil
	}
	// Map day-of-week names
	if v, ok := dowNames[s]; ok {
		if v < min || v > max {
			return 0, fmt.Errorf("value %d out of range [%d, %d]", v, min, max)
		}
		return v, nil
	}

	n, err := strconv.Atoi(s)
	if err != nil {
		return 0, fmt.Errorf("expected integer, got %q", s)
	}
	if n < min || n > max {
		return 0, fmt.Errorf("value %d out of range [%d, %d]", n, min, max)
	}
	return n, nil
}

// monthNames maps lowercase three-letter month abbreviations to [1,12].
var monthNames = map[string]int{
	"jan": 1, "feb": 2, "mar": 3, "apr": 4,
	"may": 5, "jun": 6, "jul": 7, "aug": 8,
	"sep": 9, "oct": 10, "nov": 11, "dec": 12,
}

// dowNames maps lowercase day-of-week abbreviations to [0,6] (Sunday=0).
var dowNames = map[string]int{
	"sun": 0, "mon": 1, "tue": 2, "wed": 3,
	"thu": 4, "fri": 5, "sat": 6,
}

// nextAfter returns the next time at or after (after + 1 second) that matches the expression.
// The result is always in the future relative to after.
// loc is used to evaluate the cron fields (i.e., fields are in that timezone).
func (e cronExpr) nextAfter(after time.Time, loc *time.Location) time.Time {
	// For @every expressions, the next run is simply after + duration
	if e.everyDuration > 0 {
		return after.Add(e.everyDuration)
	}

	// Advance by at least one minute and truncate to minute boundary
	t := after.Add(time.Minute).Truncate(time.Minute)
	t = t.In(loc)

	// Search up to 4 years to avoid infinite loop on pathological expressions
	limit := t.Add(4 * 366 * 24 * time.Hour)

	for t.Before(limit) {
		// Check month
		month := int(t.Month())
		if e.month&(1<<uint(month)) == 0 {
			// Advance to the first day of the next valid month
			t = advanceToNextMonth(t, e.month)
			continue
		}

		// Check day-of-month
		dom := t.Day()
		if e.dom&(1<<uint(dom)) == 0 {
			// Advance to midnight of next day
			t = midnight(t.AddDate(0, 0, 1))
			continue
		}

		// Check day-of-week
		dow := int(t.Weekday())
		if e.dow&(1<<uint(dow)) == 0 {
			t = midnight(t.AddDate(0, 0, 1))
			continue
		}

		// Check hour
		hour := t.Hour()
		if e.hour&(1<<uint(hour)) == 0 {
			// Advance to start of next valid hour
			t = advanceToNextHour(t, e.hour)
			continue
		}

		// Check minute
		minute := t.Minute()
		if e.minute&(1<<uint(minute)) == 0 {
			// Advance to next valid minute within this hour
			next := nextSetBit64(e.minute, minute+1)
			if next >= 0 {
				t = time.Date(t.Year(), t.Month(), t.Day(), t.Hour(), next, 0, 0, loc)
			} else {
				// No more valid minutes in this hour, advance to next hour
				t = advanceToNextHour(t, e.hour)
			}
			continue
		}

		// All fields match
		return t
	}

	// Fallback: should never be reached for a valid expression
	return after.Add(time.Hour)
}

// midnight returns the time at 00:00:00 on the same date as t.
func midnight(t time.Time) time.Time {
	return time.Date(t.Year(), t.Month(), t.Day(), 0, 0, 0, 0, t.Location())
}

// advanceToNextMonth returns midnight of the first day of the next valid month.
func advanceToNextMonth(t time.Time, monthBits uint16) time.Time {
	year := t.Year()
	month := int(t.Month())

	for {
		month++
		if month > 12 {
			month = 1
			year++
		}
		if monthBits&(1<<uint(month)) != 0 {
			return time.Date(year, time.Month(month), 1, 0, 0, 0, 0, t.Location())
		}
		// Guard: if we've wrapped around 4 years without a hit, give up
		if year > t.Year()+4 {
			return t.Add(24 * time.Hour)
		}
	}
}

// advanceToNextHour returns the start of the next valid hour on the same or next day.
func advanceToNextHour(t time.Time, hourBits uint32) time.Time {
	hour := t.Hour()
	next := nextSetBit32(hourBits, hour+1)
	if next >= 0 {
		return time.Date(t.Year(), t.Month(), t.Day(), next, 0, 0, 0, t.Location())
	}
	// No more valid hours today; advance to midnight of the next day
	return midnight(t.AddDate(0, 0, 1))
}

// nextSetBit64 returns the lowest set bit position >= start in a uint64, or -1 if none.
func nextSetBit64(mask uint64, start int) int {
	if start > 63 {
		return -1
	}
	// Zero all bits below start
	shifted := mask >> uint(start)
	if shifted == 0 {
		return -1
	}
	return start + bits.TrailingZeros64(shifted)
}

// nextSetBit32 returns the lowest set bit position >= start in a uint32, or -1 if none.
func nextSetBit32(mask uint32, start int) int {
	if start > 31 {
		return -1
	}
	shifted := mask >> uint(start)
	if shifted == 0 {
		return -1
	}
	return start + bits.TrailingZeros32(shifted)
}
