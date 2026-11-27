package server

import (
	"encoding/hex"
	"regexp"
	"testing"
)

func TestWebhookUUIDv7AndSignature(t *testing.T) {
	id, err := webhookUUIDv7()
	if err != nil {
		t.Fatalf("webhookUUIDv7() error = %v", err)
	}
	if matched, _ := regexp.MatchString(`^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`, id); !matched {
		t.Fatalf("webhook UUID = %q, want UUID v7", id)
	}

	secret := []byte("per-webhook secret")
	body := []byte(`{"event":"backup.failed"}`)
	signature, err := hex.DecodeString(webhookSignature(secret, body))
	if err != nil {
		t.Fatalf("decode signature: %v", err)
	}
	if len(signature) != 32 {
		t.Fatalf("signature length = %d, want 32 bytes", len(signature))
	}
}

func TestWebhookPrioritiesFollowSeverity(t *testing.T) {
	for _, test := range []struct {
		severity string
		pushover string
		gotify   int
	}{
		{severity: "info", pushover: "0", gotify: 2},
		{severity: "warning", pushover: "0", gotify: 5},
		{severity: "critical", pushover: "1", gotify: 8},
	} {
		if got := webhookPriority("pushover", test.severity); got != test.pushover {
			t.Errorf("Pushover priority for %s = %s, want %s", test.severity, got, test.pushover)
		}
		if got := gotifyPriority(test.severity); got != test.gotify {
			t.Errorf("Gotify priority for %s = %d, want %d", test.severity, got, test.gotify)
		}
	}
}
