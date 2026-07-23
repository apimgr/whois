package config

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"

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

// ConfigDir returns the platform-appropriate config directory
func ConfigDir() string {
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
	return filepath.Join(base, constants.InternalOrg, constants.InternalName)
}

// ConfigPath returns the platform-appropriate config file path
func ConfigPath() string {
	return filepath.Join(ConfigDir(), "cli.yml")
}

// fileExists reports whether path exists and is a regular file (or at least stat-able).
var fileExists = func(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

// ResolveConfigPath resolves a --config flag value to an absolute config file path
// (AI.md PART 32: "--config Flag (Config File Selection)").
//
// Resolution rules:
//  1. Empty value -> the default cli.yml path.
//  2. Absolute path (or "~/..." expanded to the home directory) -> used verbatim,
//     after yaml extension resolution.
//  3. Relative path -> resolved against ConfigDir(), then yaml extension resolution.
func ResolveConfigPath(configFlag string) string {
	if configFlag == "" {
		return ConfigPath()
	}

	if strings.HasPrefix(configFlag, "~/") {
		home, _ := os.UserHomeDir()
		configFlag = filepath.Join(home, configFlag[2:])
	}

	if filepath.IsAbs(configFlag) {
		return resolveYamlExtension(configFlag)
	}

	return resolveYamlExtension(filepath.Join(ConfigDir(), configFlag))
}

// resolveYamlExtension auto-detects .yml or .yaml extension.
// If no extension is given, it checks for an existing .yml then .yaml file,
// defaulting to .yml for new configs.
func resolveYamlExtension(path string) string {
	ext := filepath.Ext(path)

	if ext == ".yml" || ext == ".yaml" {
		return path
	}

	if ext == "" {
		if fileExists(path + ".yml") {
			return path + ".yml"
		}
		if fileExists(path + ".yaml") {
			return path + ".yaml"
		}
		return path + ".yml"
	}

	return path
}

// Load reads the default config file and returns a CLIConfig with defaults applied
func Load() (*CLIConfig, error) {
	return LoadFrom(ConfigPath())
}

// LoadFrom reads the config file at the given path and returns a CLIConfig with
// defaults applied. Use ResolveConfigPath to turn a --config flag value into path.
func LoadFrom(path string) (*CLIConfig, error) {
	cfg := &CLIConfig{
		Format: "table",
	}

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
		cfg.Format = "table"
	}

	return cfg, nil
}

// Save writes the config to the platform-appropriate path
func Save(cfg *CLIConfig) error {
	return SaveTo(ConfigPath(), cfg)
}

// SaveTo writes the config to the given path, creating parent directories as needed.
// Use ResolveConfigPath to turn a --config flag value into path.
func SaveTo(path string, cfg *CLIConfig) error {
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return err
	}

	data, err := yaml.Marshal(cfg)
	if err != nil {
		return err
	}

	return os.WriteFile(path, data, 0644)
}
