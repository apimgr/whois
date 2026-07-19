package config

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestFlattenConfigContainsExpectedKeys(t *testing.T) {
	cfg := Default()
	flat := flattenConfig(cfg)

	for _, key := range []string{"address", "port", "ssl.enabled", "database.driver", "rate_limit.global_burst"} {
		if _, ok := flat[key]; !ok {
			t.Errorf("flattenConfig() missing expected key %q", key)
		}
	}
}

func TestCompareConfigsDetectsChanges(t *testing.T) {
	oldCfg := Default()
	newCfg := Default()
	newCfg.Address = "10.0.0.1"
	newCfg.RateLimit.GlobalBurst = newCfg.RateLimit.GlobalBurst + 5

	changes := compareConfigs(oldCfg, newCfg)
	if len(changes) == 0 {
		t.Fatal("compareConfigs() reported no changes when fields differ")
	}

	found := map[string]bool{}
	for _, c := range changes {
		found[c] = true
	}
	if !found["address"] {
		t.Error("compareConfigs() did not report changed address")
	}
	if !found["rate_limit.global_burst"] {
		t.Error("compareConfigs() did not report changed rate_limit.burst")
	}
}

func TestCompareConfigsNoChanges(t *testing.T) {
	cfg := Default()
	changes := compareConfigs(cfg, cfg)
	if len(changes) != 0 {
		t.Errorf("compareConfigs() = %v, want no changes for identical configs", changes)
	}
}

func TestCategorizeChanges(t *testing.T) {
	changes := []string{"address", "port", "ssl.enabled", "database.driver", "tor.enabled", "rate_limit.global_burst", "branding.name"}
	hot, restart := categorizeChanges(changes)

	restartSet := map[string]bool{}
	for _, r := range restart {
		restartSet[r] = true
	}
	for _, want := range []string{"address", "port", "ssl.enabled", "database.driver", "tor.enabled"} {
		if !restartSet[want] {
			t.Errorf("categorizeChanges() did not classify %q as restart-required", want)
		}
	}

	hotSet := map[string]bool{}
	for _, h := range hot {
		hotSet[h] = true
	}
	for _, want := range []string{"rate_limit.global_burst", "branding.name"} {
		if !hotSet[want] {
			t.Errorf("categorizeChanges() did not classify %q as hot-reloadable", want)
		}
	}
}

func TestConfigManagerApplyHotReloadPreservesRestartFields(t *testing.T) {
	current := Default()
	current.Address = "127.0.0.1"
	current.Port = 12345

	m := &ConfigManager{current: current}

	incoming := Default()
	incoming.Address = "9.9.9.9"
	incoming.Port = 9999
	incoming.Branding.Title = "changed-name"

	m.applyHotReloadSettings(incoming)

	if current.Address != "127.0.0.1" {
		t.Errorf("Address = %q, want preserved 127.0.0.1", current.Address)
	}
	if current.Port != 12345 {
		t.Errorf("Port = %d, want preserved 12345", current.Port)
	}
	if current.Branding.Title != "changed-name" {
		t.Errorf("Branding.Title = %q, want hot-reloaded changed-name", current.Branding.Title)
	}
}

func TestConfigManagerApplyConfigChangesFlagsPendingRestart(t *testing.T) {
	current := Default()
	current.Address = "127.0.0.1"

	m := &ConfigManager{current: current}

	incoming := Default()
	incoming.Address = "10.10.10.10"

	m.applyConfigChanges(incoming)

	if !m.PendingRestart() {
		t.Fatal("PendingRestart() = false, want true after address change")
	}
	found := false
	for _, s := range m.RestartSettings() {
		if s == "address" {
			found = true
		}
	}
	if !found {
		t.Errorf("RestartSettings() = %v, want to contain \"address\"", m.RestartSettings())
	}

	m.ClearPendingRestart()
	if m.PendingRestart() {
		t.Error("PendingRestart() = true after ClearPendingRestart()")
	}
}

func TestNewConfigManagerAndCheckFileChanges(t *testing.T) {
	dir := t.TempDir()
	cfg, err := LoadServerConfig(dir)
	if err != nil {
		t.Fatalf("LoadServerConfig() error = %v", err)
	}

	m := NewConfigManager(dir, cfg)
	if m.configPath != filepath.Join(dir, "server.yml") {
		t.Errorf("configPath = %q", m.configPath)
	}

	// No file change yet — nothing should happen.
	m.checkFileChanges()

	// Touch the file with a newer mtime and re-save with a changed value.
	cfg.Branding.Title = "reloaded-name"
	if err := cfg.Save(dir); err != nil {
		t.Fatalf("Save() error = %v", err)
	}
	future := time.Now().Add(2 * time.Second)
	if err := os.Chtimes(filepath.Join(dir, "server.yml"), future, future); err != nil {
		t.Fatalf("Chtimes() error = %v", err)
	}

	m.checkFileChanges()

	if m.current.Branding.Title != "reloaded-name" {
		t.Errorf("Branding.Title = %q, want reloaded-name after checkFileChanges()", m.current.Branding.Title)
	}
}
