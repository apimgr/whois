package server

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/apimgr/whois/src/config"
)

func TestMaintenanceHealthComponentsReflectConfiguredStateAndProbes(t *testing.T) {
	root := t.TempDir()
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	cfg := config.Default()
	cfg.ConfigDir = root
	cfg.DataDir = root
	cfg.LogDir = root
	cfg.Database.Dir = root
	cfg.Tor.Binary = executable
	cfg.I2P.Enabled = true
	cfg.I2P.Binary = executable

	features, checks := MaintenanceHealthComponents(cfg)
	if !features.Tor.Enabled || features.Tor.Status != "starting" || checks.Tor != "ok" {
		t.Fatalf("maintenance Tor state = %#v, check %q", features.Tor, checks.Tor)
	}
	if !features.I2P.Enabled || features.I2P.State != "starting" || features.I2P.Status != "starting" || features.I2P.Provider != "i2pd" || checks.I2P != "ok" {
		t.Fatalf("maintenance I2P state = %#v, check %q", features.I2P, checks.I2P)
	}
	if checks.Database != "error" || checks.Cache != "ok" || checks.Disk != "ok" || checks.Scheduler != "error" {
		t.Fatalf("maintenance checks = %#v", checks)
	}

	cfg.ConfigDir = filepath.Join(root, "missing-config")
	_, checks = MaintenanceHealthComponents(cfg)
	if checks.Disk != "error" {
		t.Fatalf("maintenance disk check = %q, want error for missing config directory", checks.Disk)
	}
}
