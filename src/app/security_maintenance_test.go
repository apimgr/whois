package app

import (
	"encoding/base64"
	"testing"

	"github.com/apimgr/whois/src/config"
	"github.com/apimgr/whois/src/security"
)

func TestSecurityMaintenanceValidation(t *testing.T) {
	for _, status := range []string{"received", "triaged", "confirmed", "patching", "disclosed", "wont_fix"} {
		if !validSecurityStatus(status) {
			t.Errorf("validSecurityStatus(%q) = false", status)
		}
	}
	if validSecurityStatus("unknown") {
		t.Fatal("unknown security status accepted")
	}
	for _, severity := range []string{"critical", "high", "medium", "low", "informational"} {
		if !validSecuritySeverity(severity) {
			t.Errorf("validSecuritySeverity(%q) = false", severity)
		}
	}
	if validSecuritySeverity("urgent") {
		t.Fatal("unknown security severity accepted")
	}

	transitions := []struct {
		from, to string
		valid    bool
	}{
		{"received", "received", true},
		{"received", "confirmed", true},
		{"confirmed", "triaged", false},
		{"triaged", "wont_fix", true},
		{"disclosed", "disclosed", true},
		{"disclosed", "wont_fix", false},
		{"wont_fix", "wont_fix", true},
		{"wont_fix", "patching", false},
		{"invalid", "received", false},
	}
	for _, test := range transitions {
		if got := validSecurityTransition(test.from, test.to); got != test.valid {
			t.Errorf("validSecurityTransition(%q, %q) = %v, want %v", test.from, test.to, got, test.valid)
		}
	}
}

func TestParseSecurityUpdate(t *testing.T) {
	trackingID, options, err := parseSecurityUpdate([]string{"TRACK-1", "--status", "triaged", "--severity", "high", "--disclosure-date", "2026-11-26", "--comment", "reviewed", "by", "operator"})
	if err != nil {
		t.Fatal(err)
	}
	if trackingID != "TRACK-1" || options.status != "triaged" || options.severity != "high" || options.disclosureDate != "2026-11-26" || options.comment != "reviewed by operator" {
		t.Fatalf("parsed update = %q, %+v", trackingID, options)
	}
	if !options.statusSet || !options.severitySet || !options.dateSet || !options.commentSet {
		t.Fatalf("update presence flags = %+v", options)
	}

	for _, args := range [][]string{
		{},
		{"TRACK-1", "--status"},
		{"TRACK-1", "--severity"},
		{"TRACK-1", "--disclosure-date"},
		{"TRACK-1", "--unknown", "value"},
	} {
		if _, _, err := parseSecurityUpdate(args); err == nil {
			t.Errorf("parseSecurityUpdate(%q) unexpectedly succeeded", args)
		}
	}
}

func TestSecurityMaintenanceHelp(t *testing.T) {
	if code := runSecurityMaintenance([]string{"help"}, ""); code != 0 {
		t.Fatalf("help exit code = %d", code)
	}
}

func TestRequiresInstallationSecret(t *testing.T) {
	tests := []struct {
		action string
		args   []string
		want   bool
	}{
		{"generate", nil, true},
		{"rotate", nil, true},
		{"import", nil, true},
		{"export", []string{"export", "public"}, false},
		{"export", []string{"export", "private"}, true},
		{"list", nil, false},
	}
	for _, test := range tests {
		if got := requiresInstallationSecret(test.action, test.args); got != test.want {
			t.Errorf("requiresInstallationSecret(%q, %q) = %v, want %v", test.action, test.args, got, test.want)
		}
	}
}

func TestSecurityReportStatusNoticeRejectsUnavailableContacts(t *testing.T) {
	cfg := &config.ServerConfig{}
	securityReportStatusNotice(cfg, "", "sec_test", "triaged")
	securityReportStatusNotice(cfg, "not-encrypted", "sec_test", "triaged")

	key := make([]byte, 32)
	cfg.Security.EncryptionKey = base64.StdEncoding.EncodeToString(key)
	securityReportStatusNotice(cfg, "not-ciphertext", "sec_test", "triaged")

	ciphertext, err := security.EncryptAESGCM(key, "not-json")
	if err != nil {
		t.Fatal(err)
	}
	securityReportStatusNotice(cfg, ciphertext, "sec_test", "triaged")

	withoutEmail, err := security.EncryptAESGCM(key, `{"researcher_gpg":""}`)
	if err != nil {
		t.Fatal(err)
	}
	securityReportStatusNotice(cfg, withoutEmail, "sec_test", "triaged")
}
