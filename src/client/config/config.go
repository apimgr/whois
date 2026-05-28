package config

import (
	"os"
	"path/filepath"
	"runtime"

	"gopkg.in/yaml.v3"
)

// CLIConfig holds the CLI configuration
type CLIConfig struct {
	Server string `yaml:"server"`
	Token  string `yaml:"token"`
	Format string `yaml:"format"`
	Debug  bool   `yaml:"debug"`
}

// ConfigPath returns the platform-appropriate config file path
func ConfigPath() string {
	var base string
	if runtime.GOOS == "windows" {
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
	return filepath.Join(base, "casapps", "caswhois", "cli.yml")
}

// Load reads the config file and returns a CLIConfig with defaults applied
func Load() (*CLIConfig, error) {
	cfg := &CLIConfig{
		Format: "text",
	}

	path := ConfigPath()
	data, err := os.ReadFile(path)
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
