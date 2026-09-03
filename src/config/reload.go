package config

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"time"
)

// restartRequiredSettings lists the dot-path prefixes that cannot change
// without a full process restart (AI.md PART 8 "Requires Restart" table).
// A trailing dot covers the whole section (ssl., database., tor.).
var restartRequiredSettings = []string{
	"address",
	"port",
	"daemonize",
	"ssl.",
	"database.",
	"tor.",
}

// ConfigManager polls server.yml for external edits and hot-reloads the
// settings AI.md marks as safe to apply live, flagging anything else as
// pending-restart. Configuration is file-only — no runtime mutation API
// (AI.md PART 5/6/12).
type ConfigManager struct {
	configDir       string
	configPath      string
	lastFileModTime time.Time
	current         *ServerConfig
	pendingRestart  bool
	restartSettings []string
	mu              sync.RWMutex
}

// NewConfigManager creates a manager that watches configDir/server.yml and
// hot-reloads into the already-loaded current config in place.
func NewConfigManager(configDir string, current *ServerConfig) *ConfigManager {
	configPath := filepath.Join(configDir, "server.yml")
	var modTime time.Time
	if info, err := os.Stat(configPath); err == nil {
		modTime = info.ModTime()
	}
	return &ConfigManager{
		configDir:       configDir,
		configPath:      configPath,
		lastFileModTime: modTime,
		current:         current,
	}
}

// Start begins polling server.yml every 5 seconds for external edits
// (AI.md PART 8 — polling by design, not fsnotify).
func (m *ConfigManager) Start() {
	go func() {
		ticker := time.NewTicker(5 * time.Second)
		defer ticker.Stop()
		for range ticker.C {
			m.checkFileChanges()
		}
	}()
}

// checkFileChanges watches server.yml for external edits and hot-reloads.
func (m *ConfigManager) checkFileChanges() {
	info, err := os.Stat(m.configPath)
	if err != nil || info.ModTime().Equal(m.lastFileModTime) {
		return
	}
	m.lastFileModTime = info.ModTime()

	newConfig, err := LoadServerConfig(m.configDir)
	if err != nil {
		log.Printf("config file parse error: %v", err)
		return
	}

	m.applyConfigChanges(newConfig)
}

// ApplyExternalConfig runs a config obtained outside the polling loop (e.g.
// from a manual SIGHUP reload) through the same categorization logic, so
// hot-reloadable settings apply immediately and restart-required settings
// are only flagged, never mutated on the live process.
func (m *ConfigManager) ApplyExternalConfig(newConfig *ServerConfig) {
	m.applyConfigChanges(newConfig)
}

// applyConfigChanges categorizes changed settings and applies or flags them.
func (m *ConfigManager) applyConfigChanges(newConfig *ServerConfig) {
	m.mu.RLock()
	oldSnapshot := *m.current
	m.mu.RUnlock()

	changes := compareConfigs(&oldSnapshot, newConfig)
	if len(changes) == 0 {
		return
	}

	hotReloadable, needsRestart := categorizeChanges(changes)

	if len(hotReloadable) > 0 {
		m.applyHotReloadSettings(newConfig)
		log.Printf("config hot-reloaded from file: %v", hotReloadable)
	}

	if len(needsRestart) > 0 {
		m.mu.Lock()
		m.pendingRestart = true
		m.restartSettings = needsRestart
		m.mu.Unlock()
		log.Printf("config change requires restart, settings=%v", needsRestart)
	}
}

// applyHotReloadSettings copies newConfig onto the live config in place,
// while preserving the restart-required fields from the running config so
// the process keeps behaving consistently with its bound listener, open
// database connections, and running Tor child process until an operator
// restarts it (AI.md PART 8 "Requires Restart" table).
func (m *ConfigManager) applyHotReloadSettings(newConfig *ServerConfig) {
	m.mu.Lock()
	defer m.mu.Unlock()

	old := m.current
	newConfig.Address = old.Address
	newConfig.Port = old.Port
	newConfig.Daemonize = old.Daemonize
	newConfig.TLS = old.TLS
	newConfig.Database = old.Database
	newConfig.Tor = old.Tor

	*m.current = *newConfig
}

// PendingRestart reports whether a restart-required setting changed on disk.
func (m *ConfigManager) PendingRestart() bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.pendingRestart
}

// RestartSettings lists the dot-paths of settings awaiting a restart.
func (m *ConfigManager) RestartSettings() []string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.restartSettings
}

// ClearPendingRestart clears the pending-restart flag, e.g. after a restart.
func (m *ConfigManager) ClearPendingRestart() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.pendingRestart = false
	m.restartSettings = nil
}

// compareConfigs flattens both configs to dot-path/value pairs and returns
// the dot-paths whose values differ.
func compareConfigs(oldConfig, newConfig *ServerConfig) []string {
	oldFlat := flattenConfig(oldConfig)
	newFlat := flattenConfig(newConfig)

	var changed []string
	for key, newVal := range newFlat {
		if oldVal, ok := oldFlat[key]; !ok || oldVal != newVal {
			changed = append(changed, key)
		}
	}
	return changed
}

// flattenConfig walks a ServerConfig via reflection and returns a flat
// map of dot-notation key (from yaml tags) to its stringified value —
// e.g. "rate_limit.read" -> "100", "ssl.enabled" -> "true".
func flattenConfig(cfg *ServerConfig) map[string]string {
	out := make(map[string]string)
	flattenStruct(reflect.ValueOf(*cfg), "", out)
	return out
}

func flattenStruct(v reflect.Value, prefix string, out map[string]string) {
	if v.Kind() != reflect.Struct {
		return
	}
	t := v.Type()
	for i := 0; i < t.NumField(); i++ {
		field := t.Field(i)
		if !field.IsExported() {
			continue
		}
		tag := field.Tag.Get("yaml")
		name := strings.Split(tag, ",")[0]
		if name == "-" {
			continue
		}
		if name == "" {
			name = strings.ToLower(field.Name)
		}
		key := name
		if prefix != "" {
			key = prefix + "." + name
		}

		fv := v.Field(i)
		switch fv.Kind() {
		case reflect.Struct:
			flattenStruct(fv, key, out)
		case reflect.Slice, reflect.Array, reflect.Map:
			out[key] = fmt.Sprintf("%v", fv.Interface())
		default:
			out[key] = fmt.Sprintf("%v", fv.Interface())
		}
	}
}

// categorizeChanges splits changed dot-paths into hot-reloadable and
// restart-required settings (AI.md PART 8).
func categorizeChanges(changes []string) (hotReload, needsRestart []string) {
	for _, setting := range changes {
		requiresRestart := false
		for _, rs := range restartRequiredSettings {
			if strings.HasPrefix(setting, rs) {
				requiresRestart = true
				break
			}
		}
		if requiresRestart {
			needsRestart = append(needsRestart, setting)
		} else {
			hotReload = append(hotReload, setting)
		}
	}
	return
}
