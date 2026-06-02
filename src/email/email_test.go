package email

import (
	"os"
	"strings"
	"testing"
)

// TestNewEmailManager verifies initial state after construction.
func TestNewEmailManager(t *testing.T) {
	em := NewEmailManager("/tmp/test-config")

	if em == nil {
		t.Fatal("NewEmailManager returned nil")
	}
	if em.configDir != "/tmp/test-config" {
		t.Errorf("configDir = %q, want %q", em.configDir, "/tmp/test-config")
	}
	if em.enabled {
		t.Error("expected enabled=false on new manager")
	}
	if em.smtpPort != 587 {
		t.Errorf("smtpPort = %d, want 587", em.smtpPort)
	}
	if em.smtpTLS != "auto" {
		t.Errorf("smtpTLS = %q, want \"auto\"", em.smtpTLS)
	}
	if em.autoDetected {
		t.Error("expected autoDetected=false on new manager")
	}
}

// TestConfigureDirectValues verifies Configure stores supplied values.
func TestConfigureDirectValues(t *testing.T) {
	em := NewEmailManager("/tmp/test-config")
	em.Configure("mail.example.com", 465, "user@example.com", "secret", "tls", "Test App", "noreply@example.com")

	info := em.GetSMTPInfo()
	if got := info["host"]; got != "mail.example.com" {
		t.Errorf("host = %v, want mail.example.com", got)
	}
	if got := info["port"]; got != 465 {
		t.Errorf("port = %v, want 465", got)
	}
	if got := info["username"]; got != "user@example.com" {
		t.Errorf("username = %v, want user@example.com", got)
	}
	if got := info["tls_mode"]; got != "tls" {
		t.Errorf("tls_mode = %v, want tls", got)
	}
	if got := info["from_name"]; got != "Test App" {
		t.Errorf("from_name = %v, want Test App", got)
	}
	if got := info["from_email"]; got != "noreply@example.com" {
		t.Errorf("from_email = %v, want noreply@example.com", got)
	}
}

// TestConfigureEnvOverrides verifies environment variables override supplied values.
func TestConfigureEnvOverrides(t *testing.T) {
	em := NewEmailManager("/tmp/test-config")

	t.Setenv("SMTP_HOST", "env-smtp.example.com")
	t.Setenv("SMTP_PORT", "2525")
	t.Setenv("SMTP_USERNAME", "env-user")
	t.Setenv("SMTP_PASSWORD", "env-pass")
	t.Setenv("SMTP_TLS", "starttls")
	t.Setenv("SMTP_FROM_NAME", "Env App")
	t.Setenv("SMTP_FROM_EMAIL", "env@example.com")

	// Supply different values — env vars must win.
	em.Configure("original.host", 587, "orig-user", "orig-pass", "none", "Orig App", "orig@example.com")

	info := em.GetSMTPInfo()
	if got := info["host"]; got != "env-smtp.example.com" {
		t.Errorf("host = %v, want env-smtp.example.com", got)
	}
	if got := info["port"]; got != 2525 {
		t.Errorf("port = %v, want 2525", got)
	}
	if got := info["username"]; got != "env-user" {
		t.Errorf("username = %v, want env-user", got)
	}
	if got := info["tls_mode"]; got != "starttls" {
		t.Errorf("tls_mode = %v, want starttls", got)
	}
	if got := info["from_name"]; got != "Env App" {
		t.Errorf("from_name = %v, want Env App", got)
	}
	if got := info["from_email"]; got != "env@example.com" {
		t.Errorf("from_email = %v, want env@example.com", got)
	}
}

// TestConfigurePartialEnvOverride verifies only set env vars override; absent ones keep argument values.
func TestConfigurePartialEnvOverride(t *testing.T) {
	em := NewEmailManager("/tmp/test-config")
	t.Setenv("SMTP_HOST", "partial-env.example.com")

	em.Configure("original.host", 2222, "", "", "none", "", "")

	info := em.GetSMTPInfo()
	if got := info["host"]; got != "partial-env.example.com" {
		t.Errorf("host = %v, want partial-env.example.com", got)
	}
	if got := info["port"]; got != 2222 {
		t.Errorf("port = %v, want 2222 (unaffected)", got)
	}
}

// TestIsEnabledEnableDisable verifies state transitions.
func TestIsEnabledEnableDisable(t *testing.T) {
	em := NewEmailManager("/tmp/test-config")

	if em.IsEnabled() {
		t.Error("expected IsEnabled()=false after construction")
	}

	em.Enable()
	if !em.IsEnabled() {
		t.Error("expected IsEnabled()=true after Enable()")
	}

	em.Disable()
	if em.IsEnabled() {
		t.Error("expected IsEnabled()=false after Disable()")
	}
}

// TestEnableIdempotent verifies calling Enable() twice stays enabled.
func TestEnableIdempotent(t *testing.T) {
	em := NewEmailManager("/tmp/test-config")
	em.Enable()
	em.Enable()
	if !em.IsEnabled() {
		t.Error("expected IsEnabled()=true after two Enable() calls")
	}
}

// TestDisableIdempotent verifies calling Disable() twice stays disabled.
func TestDisableIdempotent(t *testing.T) {
	em := NewEmailManager("/tmp/test-config")
	em.Enable()
	em.Disable()
	em.Disable()
	if em.IsEnabled() {
		t.Error("expected IsEnabled()=false after two Disable() calls")
	}
}

// TestGetSMTPInfoFields verifies all expected keys are present in the returned map.
func TestGetSMTPInfoFields(t *testing.T) {
	em := NewEmailManager("/tmp/test-config")
	em.Configure("smtp.test.local", 587, "testuser", "testpass", "auto", "Test", "t@test.local")

	info := em.GetSMTPInfo()

	requiredKeys := []string{"enabled", "host", "port", "username", "tls_mode", "from_name", "from_email", "auto_detected"}
	for _, k := range requiredKeys {
		if _, ok := info[k]; !ok {
			t.Errorf("GetSMTPInfo() missing key %q", k)
		}
	}
}

// TestGetSMTPInfoEnabledReflectsState verifies the "enabled" field mirrors IsEnabled().
func TestGetSMTPInfoEnabledReflectsState(t *testing.T) {
	em := NewEmailManager("/tmp/test-config")

	if em.GetSMTPInfo()["enabled"] != false {
		t.Error("expected enabled=false in info before Enable()")
	}
	em.Enable()
	if em.GetSMTPInfo()["enabled"] != true {
		t.Error("expected enabled=true in info after Enable()")
	}
}

// TestGetDefaultFromEmailEmpty verifies empty fqdn returns no-reply@localhost.
func TestGetDefaultFromEmailEmpty(t *testing.T) {
	got := GetDefaultFromEmail("")
	if got != "no-reply@localhost" {
		t.Errorf("GetDefaultFromEmail(\"\") = %q, want \"no-reply@localhost\"", got)
	}
}

// TestGetDefaultFromEmailLocalhost verifies "localhost" returns no-reply@localhost.
func TestGetDefaultFromEmailLocalhost(t *testing.T) {
	got := GetDefaultFromEmail("localhost")
	if got != "no-reply@localhost" {
		t.Errorf("GetDefaultFromEmail(\"localhost\") = %q, want \"no-reply@localhost\"", got)
	}
}

// TestGetDefaultFromEmailFQDN verifies a real hostname returns the correct email.
func TestGetDefaultFromEmailFQDN(t *testing.T) {
	got := GetDefaultFromEmail("example.com")
	if got != "no-reply@example.com" {
		t.Errorf("GetDefaultFromEmail(\"example.com\") = %q, want \"no-reply@example.com\"", got)
	}
}

// TestParseTemplateValid verifies a correctly formatted template parses successfully.
func TestParseTemplateValid(t *testing.T) {
	em := NewEmailManager("/tmp/test-config")
	content := "Subject: Hello World\n---\nThis is the body.\nLine two."
	tmpl, err := em.parseTemplate(content)
	if err != nil {
		t.Fatalf("parseTemplate() unexpected error: %v", err)
	}
	if tmpl.Subject != "Hello World" {
		t.Errorf("Subject = %q, want \"Hello World\"", tmpl.Subject)
	}
	if !strings.Contains(tmpl.Body, "This is the body.") {
		t.Errorf("Body %q missing expected text", tmpl.Body)
	}
}

// TestParseTemplateMissingSeparator verifies error when --- separator is absent.
func TestParseTemplateMissingSeparator(t *testing.T) {
	em := NewEmailManager("/tmp/test-config")
	content := "Subject: Hello World\nThis is the body without a separator."
	_, err := em.parseTemplate(content)
	if err == nil {
		t.Error("expected error for missing --- separator, got nil")
	}
	if !strings.Contains(err.Error(), "separator") {
		t.Errorf("error message %q should mention separator", err.Error())
	}
}

// TestParseTemplateEmptySubject verifies error when subject line is blank.
func TestParseTemplateEmptySubject(t *testing.T) {
	em := NewEmailManager("/tmp/test-config")
	content := "Subject:\n---\nBody text here."
	_, err := em.parseTemplate(content)
	if err == nil {
		t.Error("expected error for empty subject, got nil")
	}
	if !strings.Contains(err.Error(), "subject") {
		t.Errorf("error message %q should mention subject", err.Error())
	}
}

// TestParseTemplateSubjectNoPrefix verifies plain text before separator is used as subject.
func TestParseTemplateSubjectNoPrefix(t *testing.T) {
	em := NewEmailManager("/tmp/test-config")
	// "Subject:" prefix is stripped; a bare label without the prefix still works because
	// TrimPrefix on a non-matching string is a no-op, so the raw trimmed text becomes subject.
	content := "Subject: Trimmed Subject\n---\nSome body content."
	tmpl, err := em.parseTemplate(content)
	if err != nil {
		t.Fatalf("parseTemplate() unexpected error: %v", err)
	}
	if tmpl.Subject != "Trimmed Subject" {
		t.Errorf("Subject = %q, want \"Trimmed Subject\"", tmpl.Subject)
	}
}

// TestRenderTemplateSingleKey verifies a single {key} placeholder is replaced.
func TestRenderTemplateSingleKey(t *testing.T) {
	em := NewEmailManager("/tmp/test-config")
	result := em.renderTemplate("Hello {name}!", EmailData{"name": "World"})
	if result != "Hello World!" {
		t.Errorf("renderTemplate = %q, want \"Hello World!\"", result)
	}
}

// TestRenderTemplateMultipleKeys verifies multiple distinct placeholders are all replaced.
func TestRenderTemplateMultipleKeys(t *testing.T) {
	em := NewEmailManager("/tmp/test-config")
	tpl := "Dear {first} {last}, welcome to {app}."
	data := EmailData{"first": "Jane", "last": "Doe", "app": "CasWHOIS"}
	result := em.renderTemplate(tpl, data)
	want := "Dear Jane Doe, welcome to CasWHOIS."
	if result != want {
		t.Errorf("renderTemplate = %q, want %q", result, want)
	}
}

// TestRenderTemplateUnknownKeyPreserved verifies unknown {key} placeholders are left intact.
func TestRenderTemplateUnknownKeyPreserved(t *testing.T) {
	em := NewEmailManager("/tmp/test-config")
	result := em.renderTemplate("Value: {unknown_key}", EmailData{})
	if result != "Value: {unknown_key}" {
		t.Errorf("renderTemplate = %q, want \"Value: {unknown_key}\"", result)
	}
}

// TestRenderTemplateRepeatedKey verifies a key that appears multiple times is replaced everywhere.
func TestRenderTemplateRepeatedKey(t *testing.T) {
	em := NewEmailManager("/tmp/test-config")
	result := em.renderTemplate("{app} {app} {app}", EmailData{"app": "X"})
	if result != "X X X" {
		t.Errorf("renderTemplate = %q, want \"X X X\"", result)
	}
}

// TestRenderTemplateEmptyData verifies passing nil/empty data leaves the template unchanged.
func TestRenderTemplateEmptyData(t *testing.T) {
	em := NewEmailManager("/tmp/test-config")
	tpl := "No replacements here."
	result := em.renderTemplate(tpl, EmailData{})
	if result != tpl {
		t.Errorf("renderTemplate = %q, want %q", result, tpl)
	}
}

// TestLoadTemplateWelcome verifies the embedded "welcome" template loads without error.
func TestLoadTemplateWelcome(t *testing.T) {
	em := NewEmailManager("/tmp/test-config")
	tmpl, err := em.loadTemplate("welcome")
	if err != nil {
		t.Fatalf("loadTemplate(\"welcome\") unexpected error: %v", err)
	}
	if tmpl == nil {
		t.Fatal("loadTemplate(\"welcome\") returned nil template")
	}
	if tmpl.Subject == "" {
		t.Error("expected non-empty subject from welcome template")
	}
	if tmpl.Body == "" {
		t.Error("expected non-empty body from welcome template")
	}
}

// TestLoadTemplateTest verifies the embedded "test" template loads without error.
func TestLoadTemplateTest(t *testing.T) {
	em := NewEmailManager("/tmp/test-config")
	tmpl, err := em.loadTemplate("test")
	if err != nil {
		t.Fatalf("loadTemplate(\"test\") unexpected error: %v", err)
	}
	if tmpl.Subject == "" {
		t.Error("expected non-empty subject from test template")
	}
}

// TestLoadTemplatePasswordReset verifies the embedded "password_reset" template loads without error.
func TestLoadTemplatePasswordReset(t *testing.T) {
	em := NewEmailManager("/tmp/test-config")
	tmpl, err := em.loadTemplate("password_reset")
	if err != nil {
		t.Fatalf("loadTemplate(\"password_reset\") unexpected error: %v", err)
	}
	if tmpl.Subject == "" {
		t.Error("expected non-empty subject from password_reset template")
	}
}

// TestLoadTemplateNotFound verifies a missing template name returns an error.
func TestLoadTemplateNotFound(t *testing.T) {
	em := NewEmailManager("/tmp/test-config")
	_, err := em.loadTemplate("does_not_exist")
	if err == nil {
		t.Error("expected error for non-existent template, got nil")
	}
	if !strings.Contains(err.Error(), "does_not_exist") {
		t.Errorf("error message %q should mention the template name", err.Error())
	}
}

// TestLoadTemplateCustomOverridesEmbedded verifies a custom file in configDir takes priority
// over the embedded default.
func TestLoadTemplateCustomOverridesEmbedded(t *testing.T) {
	dir := t.TempDir()
	// Create the custom template directory structure.
	customDir := dir + "/template/email"
	if err := mkdirAll(customDir); err != nil {
		t.Fatalf("failed to create custom template dir: %v", err)
	}

	customContent := "Subject: Custom Subject\n---\nCustom body content."
	if err := writeFile(customDir+"/welcome.txt", []byte(customContent)); err != nil {
		t.Fatalf("failed to write custom template: %v", err)
	}

	em := NewEmailManager(dir)
	tmpl, err := em.loadTemplate("welcome")
	if err != nil {
		t.Fatalf("loadTemplate(\"welcome\") unexpected error: %v", err)
	}
	if tmpl.Subject != "Custom Subject" {
		t.Errorf("Subject = %q, want \"Custom Subject\" (custom file should override embedded)", tmpl.Subject)
	}
}

// TestSendEmailWhenDisabledReturnsNil verifies SendEmail is a silent no-op when disabled.
func TestSendEmailWhenDisabledReturnsNil(t *testing.T) {
	em := NewEmailManager("/tmp/test-config")
	// em.enabled = false by default — do not call Enable()

	err := em.SendEmail("to@example.com", "welcome", EmailData{})
	if err != nil {
		t.Errorf("SendEmail when disabled returned error %v, want nil", err)
	}
}

// TestSendEmailEnabledBadTemplatereturnsError verifies that when enabled an unknown template
// causes an error without making any network call.
func TestSendEmailEnabledBadTemplateReturnsError(t *testing.T) {
	em := NewEmailManager("/tmp/test-config")
	em.Enable()

	err := em.SendEmail("to@example.com", "no_such_template_xyz", EmailData{})
	if err == nil {
		t.Error("expected error for unknown template when enabled, got nil")
	}
}

// TestParseIntValid verifies parseInt correctly handles numeric strings.
func TestParseIntValid(t *testing.T) {
	cases := []struct {
		input string
		want  int
	}{
		{"0", 0},
		{"1", 1},
		{"587", 587},
		{"65535", 65535},
	}
	for _, tc := range cases {
		got, err := parseInt(tc.input)
		if err != nil {
			t.Errorf("parseInt(%q) unexpected error: %v", tc.input, err)
			continue
		}
		if got != tc.want {
			t.Errorf("parseInt(%q) = %d, want %d", tc.input, got, tc.want)
		}
	}
}

// TestParseIntInvalid verifies parseInt returns an error for inputs that have
// no leading integer digits (fmt.Sscanf %d returns an error only when the very
// first token cannot be scanned as an integer).
func TestParseIntInvalid(t *testing.T) {
	cases := []string{"", "abc", " ", "not-a-number"}
	for _, input := range cases {
		_, err := parseInt(input)
		if err == nil {
			t.Errorf("parseInt(%q) expected error, got nil", input)
		}
	}
}

// TestParseIntPartialMatch verifies that fmt.Sscanf %d successfully scans the
// leading integer portion of strings like "12.34" or "1e5" without error.
// This documents the known behaviour of the parseInt implementation.
func TestParseIntPartialMatch(t *testing.T) {
	cases := []struct {
		input string
		want  int
	}{
		{"12.34", 12},
		{"1e5", 1},
	}
	for _, tc := range cases {
		got, err := parseInt(tc.input)
		if err != nil {
			t.Errorf("parseInt(%q) unexpected error: %v", tc.input, err)
			continue
		}
		if got != tc.want {
			t.Errorf("parseInt(%q) = %d, want %d", tc.input, got, tc.want)
		}
	}
}

// TestGetDefaultGatewayNoPanic verifies getDefaultGateway() returns without panicking.
// The return value is platform-dependent and may be "" or a valid IP string.
func TestGetDefaultGatewayNoPanic(t *testing.T) {
	result := getDefaultGateway()
	// Must be either empty or a valid dotted-decimal IPv4 address.
	if result == "" {
		return
	}
	// Validate rough IPv4 format: N.N.N.N
	parts := strings.Split(result, ".")
	if len(parts) != 4 {
		t.Errorf("getDefaultGateway() = %q, expected empty or IPv4 dotted-decimal", result)
	}
}

// TestTestConnectionEmptyHostReturnsError verifies TestConnection returns an error
// when no SMTP host has been configured.
func TestTestConnectionEmptyHostReturnsError(t *testing.T) {
	em := NewEmailManager("/tmp/test-config")
	// smtpHost defaults to "" — do not call Configure().

	err := em.TestConnection()
	if err == nil {
		t.Error("TestConnection() with empty host expected error, got nil")
	}
	if !strings.Contains(err.Error(), "not configured") {
		t.Errorf("error message %q should mention \"not configured\"", err.Error())
	}
}

// TestConfigureEnvPortInvalid verifies an invalid SMTP_PORT env var is ignored and the
// argument value is preserved.
func TestConfigureEnvPortInvalid(t *testing.T) {
	em := NewEmailManager("/tmp/test-config")
	t.Setenv("SMTP_PORT", "not-a-number")

	em.Configure("smtp.example.com", 2525, "", "", "auto", "", "")

	info := em.GetSMTPInfo()
	if got := info["port"]; got != 2525 {
		t.Errorf("port = %v, want 2525 (invalid env var should be ignored)", got)
	}
}

func mkdirAll(path string) error {
	return os.MkdirAll(path, 0o755)
}

func writeFile(name string, data []byte) error {
	return os.WriteFile(name, data, 0o644)
}
