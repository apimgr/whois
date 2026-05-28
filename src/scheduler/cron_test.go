package scheduler

import (
	"testing"
	"time"
)

// utc is a convenience alias for tests.
var utc = time.UTC

// mustParse parses a cron expression and fails the test on error.
func mustParse(t *testing.T, s string) cronExpr {
	t.Helper()
	e, err := parseCron(s)
	if err != nil {
		t.Fatalf("parseCron(%q) unexpected error: %v", s, err)
	}
	return e
}

// at builds a UTC time for test assertions.
func at(year int, month time.Month, day, hour, min int) time.Time {
	return time.Date(year, month, day, hour, min, 0, 0, utc)
}

func TestParseCronErrors(t *testing.T) {
	bad := []string{
		"",
		"* * * *",
		"* * * * * *",
		"60 * * * *",
		"* 24 * * *",
		"* * 0 * *",
		"* * * 0 *",
		"* * * 13 *",
		"* * * * 7",
		"*/0 * * * *",
		"@every -5m",
		"@every notaduration",
		"@every",
	}
	for _, s := range bad {
		_, err := parseCron(s)
		if err == nil {
			t.Errorf("parseCron(%q) expected error, got nil", s)
		}
	}
}

func TestAtShortcuts(t *testing.T) {
	cases := []struct {
		schedule string
		// after is the reference time
		after time.Time
		// want is the expected next fire time
		want time.Time
	}{
		// @yearly fires at 00:00 on Jan 1 next year
		{
			schedule: "@yearly",
			after:    at(2024, time.March, 10, 15, 30),
			want:     at(2025, time.January, 1, 0, 0),
		},
		// @annually same as @yearly
		{
			schedule: "@annually",
			after:    at(2024, time.December, 31, 23, 59),
			want:     at(2025, time.January, 1, 0, 0),
		},
		// @monthly fires at 00:00 on the 1st of next month
		{
			schedule: "@monthly",
			after:    at(2024, time.March, 5, 0, 0),
			want:     at(2024, time.April, 1, 0, 0),
		},
		// @weekly fires at 00:00 on next Sunday
		{
			schedule: "@weekly",
			after:    at(2024, time.March, 11, 0, 0), // Monday
			want:     at(2024, time.March, 17, 0, 0), // Sunday
		},
		// @daily fires at midnight the next day
		{
			schedule: "@daily",
			after:    at(2024, time.March, 10, 15, 30),
			want:     at(2024, time.March, 11, 0, 0),
		},
		// @midnight same as @daily
		{
			schedule: "@midnight",
			after:    at(2024, time.March, 10, 15, 30),
			want:     at(2024, time.March, 11, 0, 0),
		},
		// @hourly fires at the start of the next hour
		{
			schedule: "@hourly",
			after:    at(2024, time.March, 10, 15, 30),
			want:     at(2024, time.March, 10, 16, 0),
		},
	}

	for _, tc := range cases {
		e := mustParse(t, tc.schedule)
		got := e.nextAfter(tc.after, utc)
		if !got.Equal(tc.want) {
			t.Errorf("nextAfter(%q, %v) = %v, want %v", tc.schedule, tc.after, got, tc.want)
		}
	}
}

func TestEveryDuration(t *testing.T) {
	cases := []struct {
		schedule string
		after    time.Time
		want     time.Time
	}{
		{"@every 15m", at(2024, time.March, 10, 15, 30), at(2024, time.March, 10, 15, 45)},
		{"@every 1h", at(2024, time.March, 10, 15, 30), at(2024, time.March, 10, 16, 30)},
		{"@every 30s", at(2024, time.March, 10, 15, 30), time.Date(2024, time.March, 10, 15, 30, 30, 0, utc)},
		{"@every 24h", at(2024, time.March, 10, 15, 30), at(2024, time.March, 11, 15, 30)},
	}
	for _, tc := range cases {
		e := mustParse(t, tc.schedule)
		got := e.nextAfter(tc.after, utc)
		if !got.Equal(tc.want) {
			t.Errorf("nextAfter(%q, %v) = %v, want %v", tc.schedule, tc.after, got, tc.want)
		}
	}
}

func TestStandardFields(t *testing.T) {
	cases := []struct {
		schedule string
		after    time.Time
		want     time.Time
	}{
		// Every minute
		{
			"* * * * *",
			at(2024, time.March, 10, 15, 30),
			at(2024, time.March, 10, 15, 31),
		},
		// At :45 every hour
		{
			"45 * * * *",
			at(2024, time.March, 10, 15, 30),
			at(2024, time.March, 10, 15, 45),
		},
		// At :45 but we're past it; should roll to next hour
		{
			"45 * * * *",
			at(2024, time.March, 10, 15, 46),
			at(2024, time.March, 10, 16, 45),
		},
		// At 09:00 every day
		{
			"0 9 * * *",
			at(2024, time.March, 10, 9, 0), // exactly on 09:00 — next is tomorrow
			at(2024, time.March, 11, 9, 0),
		},
		// Step: every 15 minutes
		{
			"*/15 * * * *",
			at(2024, time.March, 10, 15, 0),
			at(2024, time.March, 10, 15, 15),
		},
		{
			"*/15 * * * *",
			at(2024, time.March, 10, 15, 45),
			at(2024, time.March, 10, 16, 0),
		},
		// Range: minutes 10-20
		{
			"10-20 * * * *",
			at(2024, time.March, 10, 15, 9),
			at(2024, time.March, 10, 15, 10),
		},
		{
			"10-20 * * * *",
			at(2024, time.March, 10, 15, 20),
			at(2024, time.March, 10, 16, 10),
		},
		// Specific day of month
		{
			"0 0 15 * *",
			at(2024, time.March, 10, 0, 0),
			at(2024, time.March, 15, 0, 0),
		},
		// Month wrap: we're in December, next valid is January
		{
			"0 0 1 1 *",
			at(2024, time.December, 31, 23, 59),
			at(2025, time.January, 1, 0, 0),
		},
		// Day of week: Monday only (1)
		{
			"0 9 * * 1",
			at(2024, time.March, 10, 9, 0), // Sunday
			at(2024, time.March, 11, 9, 0), // Monday
		},
		// Comma list: at 0 and 30 minutes
		{
			"0,30 * * * *",
			at(2024, time.March, 10, 15, 0),
			at(2024, time.March, 10, 15, 30),
		},
		{
			"0,30 * * * *",
			at(2024, time.March, 10, 15, 30),
			at(2024, time.March, 10, 16, 0),
		},
		// Step with range: 10-50/10 = 10,20,30,40,50
		{
			"10-50/10 * * * *",
			at(2024, time.March, 10, 15, 9),
			at(2024, time.March, 10, 15, 10),
		},
		{
			"10-50/10 * * * *",
			at(2024, time.March, 10, 15, 40),
			at(2024, time.March, 10, 15, 50),
		},
		{
			"10-50/10 * * * *",
			at(2024, time.March, 10, 15, 50),
			at(2024, time.March, 10, 16, 10),
		},
	}

	for _, tc := range cases {
		e := mustParse(t, tc.schedule)
		got := e.nextAfter(tc.after, utc)
		if !got.Equal(tc.want) {
			t.Errorf("nextAfter(%q, %v) = %v, want %v", tc.schedule, tc.after, got, tc.want)
		}
	}
}

func TestNextRunAlwaysInFuture(t *testing.T) {
	schedules := []string{
		"* * * * *",
		"@hourly",
		"@daily",
		"@weekly",
		"@monthly",
		"@yearly",
		"@every 5m",
		"0 9 * * 1",
		"*/5 * * * *",
	}
	now := time.Now().UTC()
	for _, s := range schedules {
		e := mustParse(t, s)
		got := e.nextAfter(now, utc)
		if !got.After(now) {
			t.Errorf("nextAfter(%q) = %v is not after now (%v)", s, got, now)
		}
	}
}

func TestCalculateNextRunFallback(t *testing.T) {
	// An invalid schedule should return ~1 hour from now
	before := time.Now()
	task := &Task{
		ID:       "test",
		Schedule: "invalid cron expression",
	}
	s := &Scheduler{timezone: utc}
	got := s.calculateNextRun(task)
	after := time.Now()

	lower := before.Add(59 * time.Minute)
	upper := after.Add(61 * time.Minute)
	if got.Before(lower) || got.After(upper) {
		t.Errorf("fallback time %v not in expected range [%v, %v]", got, lower, upper)
	}
}

func TestCalculateNextRunValid(t *testing.T) {
	s := &Scheduler{timezone: utc}
	task := &Task{
		ID:       "test-valid",
		Schedule: "*/5 * * * *",
	}
	now := time.Now().UTC()
	got := s.calculateNextRun(task)
	if !got.After(now) {
		t.Errorf("calculateNextRun returned %v which is not after now %v", got, now)
	}
	// Should be within 5 minutes
	if got.After(now.Add(5 * time.Minute)) {
		t.Errorf("calculateNextRun returned %v which is more than 5 minutes from now %v", got, now)
	}
}
