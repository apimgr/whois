package scheduler

import (
	"fmt"
	"strconv"
	"strings"
	"time"
)

type cronField struct {
	values    map[int]bool
	wildcard  bool
	min, max  int
}

func nextScheduledTime(schedule string, after time.Time, location *time.Location) (time.Time, error) {
	if location == nil {
		location = time.Local
	}
	schedule = strings.TrimSpace(schedule)
	if strings.HasPrefix(schedule, "@every ") {
		duration, err := time.ParseDuration(strings.TrimSpace(strings.TrimPrefix(schedule, "@every ")))
		if err != nil || duration <= 0 {
			return time.Time{}, fmt.Errorf("invalid interval schedule %q", schedule)
		}
		return after.Add(duration), nil
	}
	switch schedule {
	case "@hourly":
		schedule = "0 * * * *"
	case "@daily", "@midnight":
		schedule = "0 0 * * *"
	case "@weekly":
		schedule = "0 0 * * 0"
	case "@monthly":
		schedule = "0 0 1 * *"
	case "@yearly", "@annually":
		schedule = "0 0 1 1 *"
	}
	parts := strings.Fields(schedule)
	if len(parts) != 5 {
		return time.Time{}, fmt.Errorf("cron schedule must contain five fields")
	}
	ranges := [][2]int{{0, 59}, {0, 23}, {1, 31}, {1, 12}, {0, 7}}
	fields := make([]cronField, len(parts))
	for i, part := range parts {
		field, err := parseCronField(normalizeCronField(part, i), ranges[i][0], ranges[i][1], i == 4)
		if err != nil {
			return time.Time{}, fmt.Errorf("cron field %d: %w", i+1, err)
		}
		fields[i] = field
	}
	start := after.In(location).Truncate(time.Minute).Add(time.Minute)
	// Cron fields are evaluated on local calendar dates. Iterating dates first
	// keeps sparse schedules inexpensive and respects daylight-saving changes.
	for day := time.Date(start.Year(), start.Month(), start.Day(), 0, 0, 0, 0, location); day.Before(start.AddDate(5, 0, 0)); day = day.AddDate(0, 0, 1) {
		if !fields[3].values[int(day.Month())] || !cronDayMatches(fields[2], fields[4], day) {
			continue
		}
		for hour := 0; hour <= 23; hour++ {
			if !fields[1].values[hour] {
				continue
			}
			for minute := 0; minute <= 59; minute++ {
				if !fields[0].values[minute] {
					continue
				}
				candidate := time.Date(day.Year(), day.Month(), day.Day(), hour, minute, 0, 0, location)
				if candidate.After(after) && !candidate.Before(start) {
					return candidate, nil
				}
			}
		}
	}
	return time.Time{}, fmt.Errorf("cron schedule %q has no occurrence in the next five years", schedule)
}

func normalizeCronField(spec string, fieldIndex int) string {
	names := map[string]int{}
	switch fieldIndex {
	case 3:
		for i, name := range []string{"JAN", "FEB", "MAR", "APR", "MAY", "JUN", "JUL", "AUG", "SEP", "OCT", "NOV", "DEC"} {
			names[name] = i + 1
		}
	case 4:
		for i, name := range []string{"SUN", "MON", "TUE", "WED", "THU", "FRI", "SAT"} {
			names[name] = i
		}
	default:
		return spec
	}
	items := strings.Split(strings.ToUpper(spec), ",")
	for i, item := range items {
		parts := strings.Split(item, "/")
		bounds := strings.Split(parts[0], "-")
		for j, bound := range bounds {
			if value, ok := names[bound]; ok {
				bounds[j] = strconv.Itoa(value)
			}
		}
		parts[0] = strings.Join(bounds, "-")
		items[i] = strings.Join(parts, "/")
	}
	return strings.Join(items, ",")
}

func cronDayMatches(dayOfMonth, dayOfWeek cronField, date time.Time) bool {
	dayMatch := dayOfMonth.values[date.Day()]
	weekday := int(date.Weekday())
	weekMatch := dayOfWeek.values[weekday] || (weekday == 0 && dayOfWeek.values[7])
	if dayOfMonth.wildcard {
		return weekMatch
	}
	if dayOfWeek.wildcard {
		return dayMatch
	}
	return dayMatch || weekMatch
}

func parseCronField(spec string, min, max int, sundayAlias bool) (cronField, error) {
	field := cronField{values: make(map[int]bool), min: min, max: max, wildcard: spec == "*" || strings.HasPrefix(spec, "*/")}
	for _, item := range strings.Split(spec, ",") {
		if item == "" {
			return cronField{}, fmt.Errorf("empty list item")
		}
		base := item
		step := 1
		if parts := strings.Split(item, "/"); len(parts) > 2 {
			return cronField{}, fmt.Errorf("invalid step %q", item)
		} else if len(parts) == 2 {
			base = parts[0]
			parsed, err := strconv.Atoi(parts[1])
			if err != nil || parsed <= 0 {
				return cronField{}, fmt.Errorf("invalid step %q", item)
			}
			step = parsed
		}
		lo, hi := min, max
		if base != "*" {
			bounds := strings.Split(base, "-")
			if len(bounds) > 2 {
				return cronField{}, fmt.Errorf("invalid range %q", item)
			}
			var err error
			lo, err = strconv.Atoi(bounds[0])
			if err != nil {
				return cronField{}, fmt.Errorf("invalid value %q", bounds[0])
			}
			hi = lo
			if len(bounds) == 1 && len(strings.Split(item, "/")) == 2 {
				hi = max
			}
			if len(bounds) == 2 {
				hi, err = strconv.Atoi(bounds[1])
				if err != nil {
					return cronField{}, fmt.Errorf("invalid value %q", bounds[1])
				}
			}
		}
		if lo < min || hi > max || hi < lo {
			return cronField{}, fmt.Errorf("value range %d-%d outside %d-%d", lo, hi, min, max)
		}
		for value := lo; value <= hi; value += step {
			field.values[value] = true
		}
	}
	if sundayAlias && field.values[7] {
		field.values[0] = true
	}
	if len(field.values) == 0 {
		return cronField{}, fmt.Errorf("field selects no values")
	}
	return field, nil
}
