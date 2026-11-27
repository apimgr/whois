package server

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/apimgr/whois/src/health"
)

func TestChecksInfoJSONPreservesDatasetRegistrationOrder(t *testing.T) {
	checks := ChecksInfo{
		Database: "ok", Cache: "ok", Disk: "ok", Scheduler: "ok", Tor: "ok", I2P: "degraded",
		Datasets: []health.Result{
			{Key: "geoip_asn", Critical: false, Status: "ok"},
			{Key: "geoip_country", Critical: false, Status: "degraded"},
		},
	}
	body, err := json.Marshal(checks)
	if err != nil {
		t.Fatal(err)
	}
	text := string(body)
	wantOrder := []string{`"database"`, `"cache"`, `"disk"`, `"scheduler"`, `"tor"`, `"i2p"`, `"geoip_asn"`, `"geoip_country"`}
	previous := -1
	for _, key := range wantOrder {
		index := strings.Index(text, key)
		if index <= previous {
			t.Fatalf("checks JSON order for %s in %s", key, text)
		}
		previous = index
	}
	if strings.Contains(text, "critical") {
		t.Fatalf("internal critical flag leaked in checks JSON: %s", text)
	}
}

func TestOverallStatusIncludesDatasetCriticality(t *testing.T) {
	checks := ChecksInfo{Database: "ok", Cache: "ok", Disk: "ok", Scheduler: "ok"}
	checks.Datasets = []health.Result{{Key: "geoip_asn", Status: "error"}}
	if got := getOverallStatus(checks); got != "degraded" {
		t.Fatalf("noncritical dataset status = %q, want degraded", got)
	}
	checks.Datasets[0].Critical = true
	if got := getOverallStatus(checks); got != "unhealthy" {
		t.Fatalf("critical dataset status = %q, want unhealthy", got)
	}
}
