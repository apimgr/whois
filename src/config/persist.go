package config

import (
	"fmt"
	"html"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

const serverHeader = "# This node only: listen, identity, database, cache, ssl. The rest is in yaml.d/ and credentials are in secrets.yml.\n"

var areaForServerKey = map[string]string{
	"branding": "branding", "seo": "branding", "cors": "web", "csrf": "web", "url_detection": "web", "compression": "web", "healthz": "web", "i18n": "web",
	"pages": "pages", "contact": "contact", "privacy": "privacy", "compliance": "privacy", "tracking": "privacy",
	"security": "security", "rate_limit": "security", "geoip": "security", "limits": "security", "tokens": "security",
	"logs": "logs", "metrics": "metrics", "notifications": "notifications", "tor": "tor", "i2p": "i2p",
	"maintenance": "maintenance", "scheduler": "maintenance", "update": "maintenance", "auto_update": "maintenance", "backup": "maintenance", "restore": "maintenance",
}

var nodeServerKeys = map[string]bool{"port": true, "address": true, "fqdn": true, "mode": true, "api_version": true, "baseurl": true, "pidfile": true, "daemonize": true, "debug": true, "database": true, "cache": true, "ssl": true, "trusted_proxies": true}

func (c *ServerConfig) Save(configDir string) error {
	if configDir == "" {
		configDir = c.ConfigDir
	}
	if configDir == "" {
		return fmt.Errorf("config directory not specified")
	}
	if err := secureConfigDir(configDir); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Join(configDir, "yaml.d"), 0700); err != nil {
		return err
	}
	_ = os.Chmod(filepath.Join(configDir, "yaml.d"), 0700)
	serverData, err := marshalNodeConfig(c)
	if err != nil {
		return err
	}
	cf := ConfigFile{Server: *c, Web: c.Web}
	b, err := yaml.Marshal(cf)
	if err != nil {
		return err
	}
	var doc map[string]any
	if err = yaml.Unmarshal(b, &doc); err != nil {
		return err
	}
	fullSecrets := extractSecrets(doc)
	if len(fullSecrets) > 0 {
		if err = writeSecretMap(filepath.Join(configDir, "secrets.yml"), fullSecrets); err != nil {
			return err
		}
	}
	stripSecrets(doc)
	server, _ := doc["server"].(map[string]any)
	web, _ := doc["web"].(map[string]any)
	areas := map[string]map[string]any{}
	for key, value := range server {
		if nodeServerKeys[key] {
			continue
		}
		area := areaForServerKey[key]
		if area == "" {
			area = "app"
		}
		if areas[area] == nil {
			areas[area] = map[string]any{}
		}
		areas[area]["server"] = ensureMap(areas[area]["server"])
		areas[area]["server"].(map[string]any)[key] = value
	}
	if len(web) > 0 {
		ui, hasUI := web["ui"]
		delete(web, "ui")
		if len(web) > 0 {
			if areas["web"] == nil {
				areas["web"] = map[string]any{}
			}
			areas["web"]["web"] = web
		}
		if hasUI {
			if areas["branding"] == nil {
				areas["branding"] = map[string]any{}
			}
			areas["branding"]["web"] = map[string]any{"ui": ui}
		}
	}
	for area, body := range areas {
		data, e := yaml.Marshal(body)
		if e != nil {
			return e
		}
		if e = atomicPrivateWrite(filepath.Join(configDir, "yaml.d", area+".yml"), data); e != nil {
			return e
		}
	}
	return atomicPrivateWrite(filepath.Join(configDir, "server.yml"), serverData)
}

func marshalNodeConfig(c *ServerConfig) ([]byte, error) {
	copy := *c
	copy.ServerToken = ""
	copy.Security.EncryptionKey = ""
	copy.Pages.Contact.CaptchaSecretKey = ""
	b, err := yaml.Marshal(ConfigFile{Server: copy})
	if err != nil {
		return nil, err
	}
	var doc map[string]any
	if err = yaml.Unmarshal(b, &doc); err != nil {
		return nil, err
	}
	server, _ := doc["server"].(map[string]any)
	if c.HTTPPort > 0 && c.HTTPSPort > 0 {
		server["port"] = fmt.Sprintf("%d,%d", c.HTTPPort, c.HTTPSPort)
	}
	node := map[string]any{}
	for k, v := range server {
		if nodeServerKeys[k] {
			node[k] = v
		}
	}
	body, err := yaml.Marshal(map[string]any{"server": node})
	if err != nil {
		return nil, err
	}
	return append([]byte(serverHeader), body...), nil
}

func (c *ServerConfig) SaveSecrets(configDir string) error {
	if configDir == "" {
		configDir = c.ConfigDir
	}
	if configDir == "" {
		return fmt.Errorf("config directory not specified")
	}
	if err := secureConfigDir(configDir); err != nil {
		return err
	}
	return writeConfigSecrets(filepath.Join(configDir, "secrets.yml"), c)
}

func writeConfigSecrets(path string, c *ServerConfig) error {
	data, err := yaml.Marshal(ConfigFile{Server: *c, Web: c.Web})
	if err != nil {
		return err
	}
	var full map[string]any
	if err = yaml.Unmarshal(data, &full); err != nil {
		return err
	}
	secrets := extractSecrets(full)
	if len(secrets) == 0 {
		return nil
	}
	old := map[string]any{}
	if b, e := os.ReadFile(path); e == nil {
		if yaml.Unmarshal(b, &old) != nil {
			old = map[string]any{}
		}
	} else if !os.IsNotExist(e) {
		return e
	}
	mergeConfigMaps(old, secrets)
	b, err := yaml.Marshal(old)
	if err != nil {
		return err
	}
	return atomicPrivateWrite(path, b)
}

func extractSecrets(node map[string]any) map[string]any {
	out := map[string]any{}
	secretKeys := map[string]bool{"token": true, "encryption_key": true, "encryption_key_version": true, "password": true, "database_token": true, "captcha_secret_key": true, "dns_credentials": true, "api_key": true, "encryption_password": true}
	var walk func(dst, src map[string]any, path string)
	walk = func(dst, src map[string]any, prefix string) {
		for k, v := range src {
			p := k
			if prefix != "" {
				p = prefix + "." + k
			}
			if m, ok := v.(map[string]any); ok {
				child := map[string]any{}
				walk(child, m, p)
				if len(child) > 0 {
					dst[k] = child
				}
				continue
			}
			secret := secretKeys[k] || strings.Contains(prefix, ".webhooks") || strings.Contains(prefix, ".metrics.auth.tokens") || (k == "url" && urlHasCredentials(v))
			if secret {
				dst[k] = v
			}
		}
	}
	walk(out, node, "")
	return out
}

func urlHasCredentials(value any) bool {
	s, ok := value.(string)
	if !ok {
		return false
	}
	u, err := url.Parse(s)
	return err == nil && u.User != nil
}

func ensureMap(v any) map[string]any {
	if m, ok := v.(map[string]any); ok {
		return m
	}
	return map[string]any{}
}

func atomicPrivateWrite(path string, data []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".config-*")
	if err != nil {
		return err
	}
	name := tmp.Name()
	defer func() { _ = os.Remove(name) }()
	if err = tmp.Chmod(0600); err == nil {
		_, err = tmp.Write(data)
	}
	if err == nil {
		err = tmp.Sync()
	}
	closeErr := tmp.Close()
	if err == nil {
		err = closeErr
	}
	if err != nil {
		return err
	}
	if err = os.Rename(name, path); err != nil {
		return err
	}
	if dir, e := os.Open(filepath.Dir(path)); e == nil {
		_ = dir.Sync()
		_ = dir.Close()
	}
	return nil
}

func migrateConfigLayout(configDir string) error {
	path := filepath.Join(configDir, "server.yml")
	original, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	var doc map[string]any
	if err = yaml.Unmarshal(original, &doc); err != nil {
		return nil
	}
	legacyChanged := migrateLegacyKeys(doc)
	server, _ := doc["server"].(map[string]any)
	web, _ := doc["web"].(map[string]any)
	if server == nil {
		server = map[string]any{}
	}
	secretValues := extractSecrets(doc)
	drop := filepath.Join(configDir, "yaml.d")
	dropEntries, _ := os.ReadDir(drop)
	dropUpdates := map[string][]byte{}
	for _, entry := range dropEntries {
		name := entry.Name()
		if strings.HasPrefix(name, ".") || (!strings.HasSuffix(name, ".yml") && !strings.HasSuffix(name, ".yaml")) || strings.HasSuffix(name, ".bak") || strings.HasSuffix(name, ".orig") || strings.HasSuffix(name, "~") {
			continue
		}
		p := filepath.Join(drop, name)
		info, e := os.Lstat(p)
		if e != nil {
			continue
		}
		if info.Mode()&os.ModeSymlink != 0 {
			real, e := filepath.EvalSymlinks(p)
			base, _ := filepath.EvalSymlinks(drop)
			if e != nil || base == "" || (real != base && !strings.HasPrefix(real, base+string(filepath.Separator))) {
				continue
			}
		}
		data, e := os.ReadFile(p)
		if e != nil {
			continue
		}
		var area map[string]any
		if yaml.Unmarshal(data, &area) != nil {
			continue
		}
		found := extractSecrets(area)
		if len(found) == 0 {
			continue
		}
		mergeConfigMaps(secretValues, found)
		stripSecrets(area)
		rewritten, e := yaml.Marshal(area)
		if e != nil {
			return e
		}
		dropUpdates[p] = rewritten
	}
	if len(secretValues) > 0 {
		if err := atomicPrivateWrite(path+".bak", original); err != nil {
			return err
		}
		if err := writeSecretMap(filepath.Join(configDir, "secrets.yml"), secretValues); err != nil {
			return err
		}
		stripSecrets(doc)
		server, _ = doc["server"].(map[string]any)
		if server == nil {
			server = map[string]any{}
		}
	}
	moveServer := map[string]any{}
	moveTop := map[string]map[string]any{}
	moveWeb := map[string]any{}
	changed := false
	for key, value := range server {
		if nodeServerKeys[key] {
			continue
		}
		area := areaForServerKey[key]
		if area == "" {
			area = "app"
		}
		moveServer[area] = ensureMap(moveServer[area])
		moveServer[area].(map[string]any)[key] = value
		delete(server, key)
		changed = true
	}
	for key, value := range doc {
		if key == "server" || key == "web" {
			continue
		}
		area := "app"
		if key == "tor" {
			area = "tor"
		}
		if key == "cli" {
			area = "maintenance"
		}
		if key == "data" {
			area = "security"
		}
		moveTop[area] = ensureMap(moveTop[area])
		moveTop[area][key] = value
		delete(doc, key)
		changed = true
	}
	if len(web) > 0 {
		moveWeb = web
		delete(doc, "web")
		changed = true
	}
	if !changed && len(secretValues) == 0 && !legacyChanged {
		return nil
	}
	if err := atomicPrivateWrite(path+".bak", original); err != nil {
		return err
	}
	areaDocs := map[string]map[string]any{}
	for area, section := range moveServer {
		areaDocs[area] = map[string]any{"server": section}
	}
	for area, top := range moveTop {
		if areaDocs[area] == nil {
			areaDocs[area] = map[string]any{}
		}
		for key, value := range top {
			areaDocs[area][key] = value
		}
	}
	if len(moveWeb) > 0 {
		branding := map[string]any{}
		if ui, ok := moveWeb["ui"]; ok {
			branding["web"] = map[string]any{"ui": ui}
			delete(moveWeb, "ui")
		}
		if len(moveWeb) > 0 {
			areaDocs["web"] = map[string]any{"web": moveWeb}
		}
		if len(branding) > 0 {
			if areaDocs["branding"] == nil {
				areaDocs["branding"] = map[string]any{}
			}
			for k, v := range branding {
				areaDocs["branding"][k] = v
			}
		}
	}
	if err := os.MkdirAll(drop, 0700); err != nil {
		return err
	}
	_ = os.Chmod(drop, 0700)
	for p, data := range dropUpdates {
		if err := atomicPrivateWrite(p, data); err != nil {
			return err
		}
	}
	for area, moved := range areaDocs {
		p := filepath.Join(drop, area+".yml")
		var old map[string]any
		if b, e := os.ReadFile(p); e == nil {
			_ = yaml.Unmarshal(b, &old)
		}
		if old == nil {
			old = map[string]any{}
		}
		mergeConfigMaps(moved, old)
		b, e := yaml.Marshal(moved)
		if e != nil {
			return e
		}
		if e = atomicPrivateWrite(p, b); e != nil {
			return e
		}
	}
	if len(server) == 0 {
		delete(doc, "server")
	} else {
		doc["server"] = server
	}
	rewritten, e := yaml.Marshal(doc)
	if e != nil {
		return e
	}
	return atomicPrivateWrite(path, append([]byte(serverHeader), rewritten...))
}

func stripSecrets(node map[string]any) {
	keys := map[string]bool{"token": true, "encryption_key": true, "encryption_key_version": true, "password": true, "database_token": true, "captcha_secret_key": true, "dns_credentials": true, "api_key": true, "encryption_password": true}
	var walk func(map[string]any, string)
	walk = func(m map[string]any, prefix string) {
		for k, v := range m {
			if child, ok := v.(map[string]any); ok {
				walk(child, prefix+"."+k)
				if len(child) == 0 {
					delete(m, k)
				}
				continue
			}
			if keys[k] || strings.Contains(prefix, ".webhooks") || strings.Contains(prefix, ".metrics.auth.tokens") || (k == "url" && urlHasCredentials(v)) {
				delete(m, k)
			}
		}
	}
	walk(node, "")
}

func writeSecretMap(path string, secrets map[string]any) error {
	old := map[string]any{}
	if b, e := os.ReadFile(path); e == nil {
		if yaml.Unmarshal(b, &old) != nil {
			return fmt.Errorf("parse secrets file")
		}
	} else if !os.IsNotExist(e) {
		return e
	}
	mergeConfigMaps(secrets, old)
	b, e := yaml.Marshal(secrets)
	if e != nil {
		return e
	}
	return atomicPrivateWrite(path, b)
}

func migrateLegacyKeys(doc map[string]any) bool {
	changed := false
	server := ensureMap(doc["server"])
	doc["server"] = server
	web := ensureMap(doc["web"])
	move := func(from, to []string) {
		v, ok := takePath(doc, from)
		if !ok {
			return
		}
		if !pathExists(doc, to) || emptyValue(pathValue(doc, to)) {
			putPath(doc, to, v)
		}
		changed = true
	}
	remove := func(path []string) {
		if _, ok := takePath(doc, path); ok {
			changed = true
		}
	}
	// Rename legacy logging fields and preserve per-kind options.
	if logging, ok := server["logging"].(map[string]any); ok {
		for k, v := range logging {
			switch k {
			case "access_format":
				moveValue(doc, []string{"server", "logging", k}, []string{"server", "logs", "access", "format"}, v, &changed)
			case "level":
				moveValue(doc, []string{"server", "logging", k}, []string{"server", "logs", "level"}, v, &changed)
			default:
				if section, ok := v.(map[string]any); ok {
					for sk, sv := range section {
						moveValue(doc, []string{"server", "logging", k, sk}, []string{"server", "logs", k, sk}, sv, &changed)
					}
				}
			}
		}
		delete(server, "logging")
	}
	if schedule, ok := server["schedule"].(map[string]any); ok {
		for k, v := range schedule {
			if _, ok := v.(map[string]any); ok {
				moveValue(doc, []string{"server", "schedule", k}, []string{"server", "scheduler", k}, v, &changed)
			} else {
				changed = true
			}
		}
		delete(server, "schedule")
	}
	// Split the former server.web namespace into top-level web and privacy config.
	if legacy, ok := server["web"].(map[string]any); ok {
		if cc, ok := legacy["cookie_consent"].(map[string]any); ok {
			moveValue(doc, []string{"server", "web", "cookie_consent", "message"}, []string{"server", "privacy", "consent", "message"}, cc["message"], &changed)
			moveValue(doc, []string{"server", "web", "cookie_consent", "policy_url"}, []string{"server", "privacy", "consent", "policy", "url"}, cc["policy_url"], &changed)
			if _, ok := cc["enabled"]; ok {
				changed = true
			}
			delete(legacy, "cookie_consent")
		}
		mergeConfigMaps(legacy, web)
		doc["web"] = legacy
		delete(server, "web")
		changed = true
	}
	if old, ok := server["security_headers"].(map[string]any); ok {
		if v, ok := old["hsts"]; ok {
			moveValue(doc, []string{"server", "security_headers", "hsts"}, []string{"web", "hsts", "enabled"}, v, &changed)
		}
		if v, ok := old["hsts_max_age"]; ok {
			moveValue(doc, []string{"server", "security_headers", "hsts_max_age"}, []string{"web", "hsts", "max_age_seconds"}, v, &changed)
		}
		if len(old) > 0 {
			changed = true
		}
		delete(server, "security_headers")
	}
	if sec, ok := server["security"].(map[string]any); ok {
		for _, rule := range []struct{ old, new []string }{{[]string{"server", "security", "hsts"}, []string{"web", "hsts"}}, {[]string{"server", "security", "nel"}, []string{"web", "headers", "nel"}}, {[]string{"server", "security", "headers", "clear_site_data"}, []string{"web", "headers", "clear_site_data"}}, {[]string{"server", "security", "csrf"}, []string{"server", "csrf"}}} {
			if v, ok := takePath(doc, rule.old); ok {
				if !pathExists(doc, rule.new) {
					putPath(doc, rule.new, v)
				}
				changed = true
			}
		}
		if h, ok := sec["headers"].(map[string]any); ok && len(h) > 0 {
			delete(h, "clear_site_data")
			if len(h) > 0 {
				changed = true
				delete(sec, "headers")
			}
		}
	}
	if v, ok := takePath(doc, []string{"web", "csrf"}); ok {
		if !pathExists(doc, []string{"server", "csrf"}) {
			putPath(doc, []string{"server", "csrf"}, v)
		}
		changed = true
	}
	// Legacy top-level database section, including primary's flattened keys.
	if db, ok := doc["database"].(map[string]any); ok {
		if typ, ok := db["type"]; ok {
			if _, exists := db["driver"]; !exists {
				db["driver"] = typ
			}
			delete(db, "type")
		}
		if primary, ok := db["primary"].(map[string]any); ok {
			delete(db, "primary")
			mergeConfigMaps(db, primary)
		}
		target := ensureMap(server["database"])
		mergeConfigMaps(db, target)
		server["database"] = db
		delete(doc, "database")
		changed = true
	}
	move([]string{"server", "title"}, []string{"server", "branding", "title"})
	move([]string{"server", "description"}, []string{"server", "branding", "description"})
	for _, pair := range [][2]string{{"default_title", "title"}, {"default_description", "description"}} {
		v := pathValue(doc, []string{"server", "seo", pair[0]})
		if v != nil && (!pathExists(doc, []string{"server", "branding", pair[1]}) || emptyValue(pathValue(doc, []string{"server", "branding", pair[1]}))) {
			putPath(doc, []string{"server", "branding", pair[1]}, v)
		}
		remove([]string{"server", "seo", pair[0]})
	}
	if v := pathValue(doc, []string{"server", "seo", "opengraph", "image"}); v != nil {
		if !pathExists(doc, []string{"server", "seo", "og_image"}) {
			putPath(doc, []string{"server", "seo", "og_image"}, v)
		}
		remove([]string{"server", "seo", "opengraph", "image"})
	}
	remove([]string{"server", "seo", "opengraph", "description"})
	if v := pathValue(doc, []string{"server", "seo", "twitter", "site"}); v != nil {
		if !pathExists(doc, []string{"server", "seo", "twitter_handle"}) {
			putPath(doc, []string{"server", "seo", "twitter_handle"}, v)
		}
		remove([]string{"server", "seo", "twitter", "site"})
	}
	for _, p := range [][]string{{"server", "seo", "enabled"}, {"server", "seo", "sitemap", "enabled"}, {"server", "seo", "feed", "enabled"}} {
		remove(p)
	}
	move([]string{"server", "branding", "logo_url"}, []string{"server", "branding", "logo"})
	move([]string{"server", "branding", "favicon_url"}, []string{"server", "branding", "favicon"})
	move([]string{"server", "branding", "primary_color"}, []string{"web", "ui", "accent"})
	if v, ok := takePath(doc, []string{"server", "branding", "footer_text"}); ok {
		body := map[string]any{"format": "html", "body": "<p>" + html.EscapeString(fmt.Sprint(v)) + "</p>"}
		if !pathExists(doc, []string{"server", "branding", "content", "footer"}) {
			putPath(doc, []string{"server", "branding", "content", "footer"}, body)
		}
		changed = true
	}
	for _, p := range [][]string{{"server", "branding", "theme_color"}, {"server", "branding", "source_code_url"}, {"server", "admin", "path"}, {"server", "admin", "password"}, {"server", "admin", "token"}, {"server", "admin", "username"}, {"server", "admin", "two_factor"}, {"server", "seo", "sitemap", "enabled"}, {"server", "seo", "feed", "enabled"}} {
		remove(p)
	}
	move([]string{"web", "favicon_url"}, []string{"server", "branding", "favicon"})
	move([]string{"web", "ui", "favicon"}, []string{"server", "branding", "favicon"})
	move([]string{"web", "ui", "logo"}, []string{"server", "branding", "logo"})
	if v, ok := takePath(doc, []string{"web", "footer", "custom_html"}); ok {
		if !pathExists(doc, []string{"server", "branding", "content", "footer"}) {
			putPath(doc, []string{"server", "branding", "content", "footer"}, map[string]any{"format": "html", "body": v})
		}
		changed = true
	}
	for _, page := range []string{"about", "privacy", "terms"} {
		p := []string{"server", "pages", page, "content"}
		if v, ok := takePath(doc, p); ok {
			if !pathExists(doc, []string{"server", "branding", "content", page}) {
				putPath(doc, []string{"server", "branding", "content", page}, map[string]any{"format": "md", "body": v})
			}
			changed = true
		}
	}
	move([]string{"server", "admin", "email"}, []string{"server", "contact", "admin", "email"})
	// The split-port listener is represented textually by the current spec; if
	// the legacy values are numeric, preserve the requested pair for migration.
	if https, ok := takePath(doc, []string{"server", "https_port"}); ok {
		port := pathValue(doc, []string{"server", "port"})
		if n, ok := number(port); ok && n > 0 {
			if h, ok := number(https); ok && h > 0 {
				putPath(doc, []string{"server", "port"}, fmt.Sprintf("%d,%d", n, h))
			}
		}
		changed = true
	}
	if dns, ok := takePath(doc, []string{"server", "ssl", "dns01"}); ok {
		target := ensurePath(doc, []string{"server", "ssl", "letsencrypt"})
		if m, ok := dns.(map[string]any); ok {
			for k, v := range m {
				switch k {
				case "provider":
					if _, exists := target["dns_provider"]; !exists {
						target["dns_provider"] = v
					}
				case "credentials":
					if _, exists := target["dns_credentials"]; !exists {
						target["dns_credentials"] = v
					}
				}
			}
		}
		changed = true
	}
	for old, new := range map[string]string{"provider": "dns_provider", "credentials_encrypted": "dns_credentials"} {
		p := []string{"server", "ssl", "letsencrypt", old}
		if v, ok := takePath(doc, p); ok {
			q := []string{"server", "ssl", "letsencrypt", new}
			if !pathExists(doc, q) {
				putPath(doc, q, v)
			}
			changed = true
		}
	}
	for _, key := range []string{"validated_at", "domain", "domains"} {
		remove([]string{"server", "ssl", "letsencrypt", key})
	}
	for _, p := range [][]string{{"web", "llms", "enabled"}, {"server", "privacy", "content"}, {"server", "mcp"}, {"server", "rate_limit", "enabled"}, {"server", "rate_limit", "requests"}, {"server", "rate_limit", "window"}, {"server", "scheduler", "enabled"}, {"server", "maintenance_mode"}, {"server", "i18n", "auto_detect"}, {"server", "i18n", "rtl_languages"}, {"server", "i18n", "show_selector"}, {"server", "i18n", "translations_dir"}, {"server", "geoip", "dir"}, {"server", "geoip", "databases"}, {"server", "geoip", "country_mode"}, {"server", "database", "sqlite"}, {"server", "metrics", "endpoint"}, {"server", "notifications", "email_enabled"}, {"server", "notifications", "webhook_enabled"}, {"server", "secret_key"}, {"web", "permissions_policy"}, {"web", "honor_dnt"}, {"web", "robots", "ai_bots"}} {
		remove(p)
	}
	for _, p := range [][]string{{"server", "security", "installation_secret"}, {"server", "security", "installation_secret_previous"}, {"server", "security", "installation_secret_previous_expires"}, {"server", "security", "encryption_key_previous"}, {"server", "security", "encryption_key_previous_expires"}} {
		if pathExists(doc, p) {
			fmt.Printf("WARNING: legacy database secret %s must be imported to app_secrets before removal\n", strings.Join(p, "."))
		}
	}
	if tasks, ok := pathValue(doc, []string{"server", "scheduler", "tasks"}).(map[string]any); ok {
		for name, value := range tasks {
			if task, ok := value.(map[string]any); ok {
				for key := range task {
					if key != "enabled" && key != "schedule" && key != "retry_on_fail" && key != "retry_delay" {
						delete(task, key)
						changed = true
					}
				}
				tasks[name] = task
			} else {
				delete(tasks, name)
				changed = true
			}
		}
	}
	return changed
}

func moveValue(doc map[string]any, from, to []string, value any, changed *bool) {
	if value == nil {
		return
	}
	if !pathExists(doc, to) {
		putPath(doc, to, value)
	}
	takePath(doc, from)
	*changed = true
}
func pathValue(root map[string]any, path []string) any {
	var cur any = root
	for _, key := range path {
		m, ok := cur.(map[string]any)
		if !ok {
			return nil
		}
		cur = m[key]
	}
	return cur
}
func pathExists(root map[string]any, path []string) bool {
	if len(path) == 0 {
		return false
	}
	m := root
	for _, key := range path[:len(path)-1] {
		n, ok := m[key].(map[string]any)
		if !ok {
			return false
		}
		m = n
	}
	_, ok := m[path[len(path)-1]]
	return ok
}
func putPath(root map[string]any, path []string, value any) {
	if len(path) == 0 {
		return
	}
	m := root
	for _, key := range path[:len(path)-1] {
		n, ok := m[key].(map[string]any)
		if !ok {
			n = map[string]any{}
			m[key] = n
		}
		m = n
	}
	m[path[len(path)-1]] = value
}
func takePath(root map[string]any, path []string) (any, bool) {
	if len(path) == 0 {
		return nil, false
	}
	m := root
	for _, key := range path[:len(path)-1] {
		n, ok := m[key].(map[string]any)
		if !ok {
			return nil, false
		}
		m = n
	}
	v, ok := m[path[len(path)-1]]
	if ok {
		delete(m, path[len(path)-1])
	}
	return v, ok
}
func ensurePath(root map[string]any, path []string) map[string]any {
	if len(path) == 0 {
		return root
	}
	v, ok := pathValue(root, path).(map[string]any)
	if ok {
		return v
	}
	v = map[string]any{}
	putPath(root, path, v)
	return v
}
func emptyValue(v any) bool { return v == nil || v == "" }
func number(v any) (int, bool) {
	switch n := v.(type) {
	case int:
		return n, true
	case int64:
		return int(n), true
	case uint64:
		return int(n), true
	case float64:
		return int(n), n == float64(int(n))
	}
	return 0, false
}
