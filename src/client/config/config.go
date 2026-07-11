package config

import (
	"os"
	"path/filepath"
	"runtime"

	"github.com/apimgr/whois/src/common/constants"
	"gopkg.in/yaml.v3"
)

// CLIConfig holds the CLI configuration
type CLIConfig struct {
	Server        string `yaml:"server"`
	Token         string `yaml:"token"`
	Format        string `yaml:"format"`
	Lang          string `yaml:"lang"`
	UpdateChannel string `yaml:"update_channel"`
	Debug         bool   `yaml:"debug"`
}

// getOS returns the current operating system name; overridable in tests.
var getOS = func() string { return runtime.GOOS }

// readFile reads a file's contents; overridable in tests to inject errors.
var readFile = os.ReadFile

// ConfigPath returns the platform-appropriate config file path
func ConfigPath() string {
	var base string
	if getOS() == "windows" {
		base = os.Getenv("APPDATA")
		if base == "" {
			base = filepath.Join(os.Getenv("USERPROFILE"), "AppData", "Roaming")
		}
	} else {
		base = os.Getenv("XDG_CONFIG_HOME")
		if base == "" {
			home, _ := os.UserHomeDir()
			base = filepath.Join(home, ".config")
		}
	}
	return filepath.Join(base, constants.InternalOrg, constants.InternalName, "cli.yml")
}

// Load reads the config file and returns a CLIConfig with defaults applied
func Load() (*CLIConfig, error) {
	cfg := &CLIConfig{
		Format: "text",
	}

	path := ConfigPath()
	data, err := readFile(path)
	if os.IsNotExist(err) {
		return cfg, nil
	}
	if err != nil {
		return nil, err
	}

	if err := yaml.Unmarshal(data, cfg); err != nil {
		return nil, err
	}

	if cfg.Format == "" {
		cfg.Format = "text"
	}

	return cfg, nil
}

// Save writes the config to the platform-appropriate path
func Save(cfg *CLIConfig) error {
	path := ConfigPath()
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return err
	}

	data, err := yaml.Marshal(cfg)
	if err != nil {
		return err
	}

	return os.WriteFile(path, data, 0644)
}
