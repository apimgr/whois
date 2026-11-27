package config

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"sync"

	"gopkg.in/yaml.v3"
)

var dropinLastGood sync.Map

// mergedConfigYAML returns a single YAML document with defaults, server.yml,
// area files, and credentials applied in the precedence specified by AI.md.
func mergedConfigYAML(configDir string, defaults *ServerConfig, includeSecrets bool) ([]byte, error) {
	base, err := yaml.Marshal(ConfigFile{Server: *defaults})
	if err != nil {
		return nil, err
	}
	var merged map[string]any
	if err := yaml.Unmarshal(base, &merged); err != nil {
		return nil, err
	}
	var defaultMap map[string]any
	_ = yaml.Unmarshal(base, &defaultMap)
	sources := map[string]string{}
	apply := func(data []byte, source string) bool {
		var root yaml.Node
		if err := yaml.Unmarshal(data, &root); err != nil {
			log.Printf("config file parse error in %s: %v", source, err)
			if last, ok := dropinLastGood.Load(source); ok {
				mergeConfigMaps(merged, last.(map[string]any))
				return true
			}
			return false
		}
		if len(root.Content) == 0 {
			return true
		}
		next, ok := mappingFromNode(root.Content[0], defaultMap, source, "")
		if !ok {
			log.Printf("config file parse error in %s: root must be a mapping", source)
			return false
		}
		mergeConfigMapsFrom(merged, next, sources, source, "")
		dropinLastGood.Store(source, next)
		return true
	}
	serverPath := filepath.Join(configDir, "server.yml")
	data, err := os.ReadFile(serverPath)
	if err != nil && !os.IsNotExist(err) {
		return nil, fmt.Errorf("failed to read config: %w", err)
	}
	if err == nil {
		apply(data, serverPath)
	}

	dropDir := filepath.Join(configDir, "yaml.d")
	if err := os.MkdirAll(dropDir, 0700); err == nil {
		_ = os.Chmod(dropDir, 0700)
	}
	entries, err := os.ReadDir(dropDir)
	if err != nil && !os.IsNotExist(err) {
		log.Printf("read config drop-in directory %s: %v", dropDir, err)
	}
	paths := make([]string, 0)
	for _, entry := range entries {
		name := entry.Name()
		if strings.HasPrefix(name, ".") || strings.HasSuffix(name, ".bak") || strings.HasSuffix(name, "~") || strings.HasSuffix(name, ".orig") {
			continue
		}
		if !strings.HasSuffix(name, ".yml") && !strings.HasSuffix(name, ".yaml") {
			continue
		}
		p := filepath.Join(dropDir, name)
		info, statErr := os.Lstat(p)
		if statErr != nil {
			continue
		}
		if info.Mode()&os.ModeSymlink != 0 {
			real, realErr := filepath.EvalSymlinks(p)
			base, _ := filepath.EvalSymlinks(dropDir)
			if realErr != nil || base == "" || (real != base && !strings.HasPrefix(real, base+string(filepath.Separator))) {
				continue
			}
			info, statErr = os.Stat(p)
		}
		if statErr != nil || !info.Mode().IsRegular() {
			continue
		}
		if info.Mode().Perm()&0022 != 0 {
			if os.Chmod(p, 0600) != nil {
				log.Printf("ignoring writable config drop-in %s", p)
				continue
			}
		}
		paths = append(paths, p)
	}
	sort.Strings(paths)
	for _, p := range paths {
		data, readErr := os.ReadFile(p)
		if readErr != nil {
			log.Printf("read config drop-in %s: %v", p, readErr)
			continue
		}
		if apply(data, p) {
			log.Printf("loaded config drop-in: %s", p)
		}
	}
	secretsPath := filepath.Join(configDir, "secrets.yml")
	if data, err := os.ReadFile(secretsPath); includeSecrets && err == nil {
		var root yaml.Node
		if yaml.Unmarshal(data, &root) != nil {
			log.Printf("config file parse error in %s", secretsPath)
			if last, ok := dropinLastGood.Load(secretsPath); ok {
				mergeSecretSources(merged, last.(map[string]any), sources, secretsPath, "", "")
			}
		} else if len(root.Content) > 0 {
			if secrets, ok := mappingFromNode(root.Content[0], defaultMap, secretsPath, ""); ok {
				dropinLastGood.Store(secretsPath, secrets)
				mergeSecretSources(merged, secrets, sources, secretsPath, "", "")
			}
		}
	}
	return yaml.Marshal(merged)
}

// EarlyConfig contains only the listener/process settings read before a privileged bind.
type EarlyConfig struct {
	Port      int       `yaml:"port"`
	HTTPPort  int       `yaml:"-"`
	HTTPSPort int       `yaml:"-"`
	Address   string    `yaml:"address"`
	Daemonize bool      `yaml:"daemonize"`
	PIDFile   bool      `yaml:"pidfile"`
	I2P       I2PConfig `yaml:"i2p"`
}

// LoadEarlyConfig reads listener settings from the same ordered file merge as
// the full loader, without opening secrets.yml.
func LoadEarlyConfig(configDir string) (*EarlyConfig, error) {
	if configDir == "" {
		return nil, fmt.Errorf("config directory not specified")
	}
	data, err := mergedConfigYAML(configDir, Default(), false)
	if err != nil {
		return nil, err
	}
	var cf ConfigFile
	var httpPort, httpsPort int
	data, httpPort, httpsPort = normalizeServerPort(data)
	if err := yaml.Unmarshal(data, &cf); err != nil {
		return nil, fmt.Errorf("parse early config: %w", err)
	}
	if httpPort == 0 && cf.Server.Port > 0 {
		httpPort, httpsPort = classifySinglePort(cf.Server.Port)
	}
	return &EarlyConfig{Port: cf.Server.Port, HTTPPort: httpPort, HTTPSPort: httpsPort, Address: cf.Server.Address, Daemonize: cf.Server.Daemonize, PIDFile: cf.Server.PIDFile, I2P: cf.Server.I2P}, nil
}

// normalizeServerPort lets the legacy integer-backed config model accept the
// project-wide single or dual listener syntax while retaining the first port
// in server.port for older callers.
func normalizeServerPort(data []byte) ([]byte, int, int) {
	var root yaml.Node
	if yaml.Unmarshal(data, &root) != nil || len(root.Content) == 0 {
		return data, 0, 0
	}
	var server *yaml.Node
	for i := 0; i+1 < len(root.Content[0].Content); i += 2 {
		if root.Content[0].Content[i].Value == "server" {
			server = root.Content[0].Content[i+1]
			break
		}
	}
	if server == nil || server.Kind != yaml.MappingNode {
		return data, 0, 0
	}
	for i := 0; i+1 < len(server.Content); i += 2 {
		if server.Content[i].Value != "port" {
			continue
		}
		portNode := server.Content[i+1]
		portNode.Style = 0
		parts := strings.Split(strings.TrimSpace(portNode.Value), ",")
		if portNode.Kind != yaml.ScalarNode || len(parts) > 2 {
			log.Printf("WARN: invalid server.port value %q; using random port assignment", portNode.Value)
			portNode.Tag, portNode.Value = "!!int", "0"
			out, err := yaml.Marshal(&root)
			if err != nil {
				return data, 0, 0
			}
			return out, 0, 0
		}
		ports := make([]int, len(parts))
		for n, part := range parts {
			p, err := strconv.Atoi(strings.TrimSpace(part))
			if err != nil || p < 1 || p > 65535 {
				log.Printf("WARN: invalid server.port value %q; using random port assignment", portNode.Value)
				portNode.Tag, portNode.Value = "!!int", "0"
				out, marshalErr := yaml.Marshal(&root)
				if marshalErr != nil {
					return data, 0, 0
				}
				return out, 0, 0
			}
			ports[n] = p
		}
		portNode.Tag = "!!int"
		portNode.Value = strconv.Itoa(ports[0])
		out, err := yaml.Marshal(&root)
		if err != nil {
			return data, 0, 0
		}
		if len(ports) == 1 {
			http, https := classifySinglePort(ports[0])
			return out, http, https
		}
		return out, ports[0], ports[1]
	}
	return data, 0, 0
}

func classifySinglePort(port int) (int, int) {
	if port == 443 {
		return 0, port
	}
	return port, 0
}

func mappingFromNode(node *yaml.Node, defaults map[string]any, file, prefix string) (map[string]any, bool) {
	if node.Kind != yaml.MappingNode {
		return nil, false
	}
	out := map[string]any{}
	seen := map[string]bool{}
	for i := 0; i+1 < len(node.Content); i += 2 {
		keyNode, valueNode := node.Content[i], node.Content[i+1]
		key := keyNode.Value
		path := key
		if prefix != "" {
			path = prefix + "." + key
		}
		if prefix != "" {
			if _, known := configFieldType(prefix, key); !known {
				log.Printf("WARNING: ignoring unknown config %s:%d key %s", file, keyNode.Line, path)
				continue
			}
		}
		if seen[key] {
			log.Printf("WARNING: invalid config %s:%d key %s: duplicate key; using default", file, keyNode.Line, path)
			if d, ok := defaults[key]; ok {
				out[key] = d
			} else {
				delete(out, key)
			}
			continue
		}
		seen[key] = true
		if valueNode.Tag == "!!null" {
			log.Printf("WARNING: invalid config %s:%d key %s: null is not allowed; using default", file, valueNode.Line, path)
			if d, ok := defaults[key]; ok {
				out[key] = d
			}
			continue
		}
		if valueNode.Kind == yaml.MappingNode {
			childDefaults, _ := defaults[key].(map[string]any)
			child, ok := mappingFromNode(valueNode, childDefaults, file, path)
			if !ok {
				return nil, false
			}
			out[key] = child
			continue
		}
		var value any
		if err := valueNode.Decode(&value); err != nil {
			log.Printf("WARNING: invalid config %s:%d key %s: %v", file, valueNode.Line, path, err)
			if d, ok := defaults[key]; ok {
				out[key] = d
			}
			continue
		}
		out[key] = value
	}
	return out, true
}

func configFieldType(prefix, key string) (reflect.Type, bool) {
	t := reflect.TypeOf(ConfigFile{})
	for _, part := range strings.Split(prefix, ".") {
		var ok bool
		t, ok = structFieldType(t, part)
		if !ok {
			return nil, false
		}
	}
	return structFieldType(t, key)
}

func structFieldType(t reflect.Type, name string) (reflect.Type, bool) {
	for t.Kind() == reflect.Pointer || t.Kind() == reflect.Slice || t.Kind() == reflect.Array {
		t = t.Elem()
	}
	if t.Kind() != reflect.Struct {
		return nil, false
	}
	for i := 0; i < t.NumField(); i++ {
		f := t.Field(i)
		tag := strings.Split(f.Tag.Get("yaml"), ",")[0]
		if tag == "" {
			tag = strings.ToLower(f.Name)
		}
		if tag == name {
			return f.Type, true
		}
	}
	return nil, false
}

func mergeConfigMaps(dst, src map[string]any) {
	for key, value := range src {
		if nested, ok := value.(map[string]any); ok {
			if existing, ok := dst[key].(map[string]any); ok {
				mergeConfigMaps(existing, nested)
				continue
			}
		}
		dst[key] = value
	}
}

func mergeConfigMapsFrom(dst, src map[string]any, sources map[string]string, source, prefix string) {
	for key, value := range src {
		path := key
		if prefix != "" {
			path = prefix + "." + key
		}
		if nested, ok := value.(map[string]any); ok {
			if old, ok := dst[key].(map[string]any); ok {
				mergeConfigMapsFrom(old, nested, sources, source, path)
				continue
			}
		}
		if _, exists := dst[key]; exists && sources[path] != "" {
			log.Printf("DEBUG: config key %s overridden by %s (previously %s)", path, source, sources[path])
		}
		dst[key] = value
		markSources(value, sources, source, path)
	}
}
func markSources(value any, sources map[string]string, source, path string) {
	if m, ok := value.(map[string]any); ok {
		for k, v := range m {
			p := path + "." + k
			markSources(v, sources, source, p)
		}
		return
	}
	sources[path] = source
}
func mergeSecretSources(dst, secrets map[string]any, sources map[string]string, source, prefix, unused string) {
	allowed := map[string]bool{"token": true, "encryption_key": true, "encryption_key_version": true, "password": true, "url": true, "database_token": true, "captcha_secret_key": true, "dns_credentials": true, "api_key": true, "encryption_password": true, "auth": true, "webhooks": true}
	for k, v := range secrets {
		p := k
		if prefix != "" {
			p = prefix + "." + k
		}
		if child, ok := v.(map[string]any); ok {
			if d, ok := dst[k].(map[string]any); ok {
				mergeSecretSources(d, child, sources, source, p, "")
			}
			continue
		}
		if allowed[k] || strings.Contains(prefix, ".webhooks") || strings.Contains(prefix, ".metrics.auth.tokens") {
			if _, exists := dst[k]; exists && sources[p] != "" {
				log.Printf("DEBUG: config key %s overridden by %s (previously %s)", p, source, sources[p])
			}
			dst[k] = v
			sources[p] = source
		}
	}
}
